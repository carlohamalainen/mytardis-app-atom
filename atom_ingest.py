import feedparser
import iso8601
from posixpath import basename
from django.template import Context
from django.contrib.sites.models import Site
from django.contrib.auth.models import User
from tardis.tardis_portal.auth.localdb_auth import django_user
from tardis.tardis_portal.fetcher import get_credential_handler
from tardis.tardis_portal.ParameterSetManager import ParameterSetManager
from tardis.tardis_portal.models import Dataset, DatasetParameter, \
    Experiment, ExperimentACL, ExperimentParameter, ParameterName, Schema, \
    Dataset_File, User, UserProfile, Author_Experiment
from tardis.tardis_portal.auth import AuthService
from tardis.tardis_portal.tasks import email_user_task
from django.db import transaction
from django.conf import settings
import urllib2
from datetime import datetime
from pytz import reference

# Ensure filters are loaded
try:
    from tardis.tardis_portal.filters import FilterInitMiddleware
    FilterInitMiddleware()
except Exception:
    pass
# Ensure logging is configured
try:
    from tardis.tardis_portal.logging_middleware import LoggingMiddleware
    LoggingMiddleware()
except Exception:
    pass

import logging
logger = logging.getLogger(__name__)

class AtomImportSchemas:

    BASE_NAMESPACE = 'http://mytardis.org/schemas/atom-import'


    @classmethod
    def get_schemas(cls):
        cls._load_fixture_if_necessary();
        return cls._get_all_schemas();

    @classmethod
    def get_schema(cls, schema_type=Schema.DATASET):
        cls._load_fixture_if_necessary();
        return Schema.objects.get(namespace__startswith=cls.BASE_NAMESPACE,
                                  type=schema_type)

    @classmethod
    def _load_fixture_if_necessary(cls):
        if (cls._get_all_schemas().count() == 0):
            from django.core.management import call_command
            call_command('loaddata', 'atom_ingest_schema')

    @classmethod
    def _get_all_schemas(cls):
        return Schema.objects.filter(namespace__startswith=cls.BASE_NAMESPACE)



class AtomPersister:

    PARAM_ENTRY_ID = 'EntryID'
    PARAM_EXPERIMENT_ID = 'ExperimentID'
    PARAM_UPDATED = 'Updated'
    PARAM_EXPERIMENT_TITLE = 'ExperimentTitle'


    def is_new(self, feed, entry):
        '''
        :param feed: Feed context for entry
        :param entry: Entry to check
        returns a boolean
        '''
        try:
            self._get_dataset(feed, entry)
            return False
        except Dataset.DoesNotExist:
            return True


    def is_updated(self, feed, entry):
        '''
        :param feed: Feed context for entry
        :param entry: Entry to check
        returns a boolean
        '''
        try:
            dataset = self._get_dataset(feed, entry)

            dataset_latest_modification_time = datetime.fromtimestamp(0)
            for df in Dataset_File.objects.filter(dataset_id=dataset.id):
                if df.modification_time is None:
                    continue
                if df.modification_time > dataset_latest_modification_time:
                    dataset_latest_modification_time = df.modification_time

            return iso8601.parse_date(entry.updated) > dataset_latest_modification_time.replace(tzinfo=reference.LocalTimezone()) 

        except Dataset.DoesNotExist:
            return False


    def _get_dataset(self, feed, entry):
        try:
            param_name = ParameterName.objects.get(name=self.PARAM_ENTRY_ID,
                                                   schema=AtomImportSchemas.get_schema())
            parameter = DatasetParameter.objects.get(name=param_name,
                                                     string_value=entry.id)
        except DatasetParameter.DoesNotExist:
            raise Dataset.DoesNotExist
        return parameter.parameterset.dataset


    def _create_entry_parameter_set(self, dataset, entryId, updated):
        namespace = AtomImportSchemas.get_schema(Schema.DATASET).namespace
        mgr = ParameterSetManager(parentObject=dataset, schema=namespace)
        mgr.new_param(self.PARAM_ENTRY_ID, entryId)
        mgr.new_param(self.PARAM_UPDATED, iso8601.parse_date(updated))


    def _create_experiment_id_parameter_set(self, experiment, experimentId):
        namespace = AtomImportSchemas.get_schema(Schema.EXPERIMENT).namespace
        mgr = ParameterSetManager(parentObject=experiment, schema=namespace)
        mgr.new_param(self.PARAM_EXPERIMENT_ID, experimentId)


    def _get_user_from_entry(self, entry):
        try:
            if entry.author_detail.email is not None:
                logger.info('User has an email address: %s'
                             % entry.author_detail.email)
                return User.objects.get(email=entry.author_detail.email)
        except (User.DoesNotExist, AttributeError):
            pass
        # Handle spaces in name
        username_ = entry.author_detail.name.strip().replace(" ", "_")
        try:
            user = User.objects.get(username=username_)
            logger.info('username %s exists' % username_)
            return user
        except User.DoesNotExist:
            pass
        logger.info('Creating user %s' % username_)
        user = self._create_user_from_entry(username_)
        return user

    def _create_user_from_entry(self, username):
        user = self._default_create_user(username)
        logger.info('tried to create user %s with result: %s' % (username, user))

        if not user:
            logger.info('No default user found, creating localdb user')
            authService = AuthService()

            userdict = {"id": username,
                        "first_name": username,
                        "last_name": "",
                        "email": settings.EMAIL_HOST_USER}

            user = authService._get_or_create_user_from_dict(
                userdict, 'localdb')

            self._email_staff(user)
        else:
            authmethod = ""
            for authKey, authDisplayName, authBackend in settings.AUTH_PROVIDERS:
                if settings.STAGING_PROTOCOL == authKey:
                    authmethod = authDisplayName

            logger.info('sending email to %s for new account' % user.email)
            self._email_user_nopass(user, authmethod)

        return user

    def _email_user_nopass(self, user, authmethod):
        protocol = ""

        if settings.IS_SECURE:
            protocol = "s"
        
        current_site_complete = "http%s://%s" % (protocol, Site.objects.get_current().domain)

        context = Context({
            'username': user.username,
            'first_name': user.first_name,
            'current_site': current_site_complete,
            'authmethod': authmethod, })

        subject = '[MyTardis] New Account Created'

        logger.info('email task dispatched to %s' % user.email)
        email_user_task.delay(subject, 'user_creation_nopass', context, user)

    def _email_staff(self, user):
        protocol = ""

        if settings.IS_SECURE:
            protocol = "s"

        current_site_complete = "http%s://%s" % (protocol, Site.objects.get_current().domain)

        context = Context({
            'username': user.username,
            'current_site': current_site_complete, })

        subject = '[MyTardis] New Account Created For External User'

        us = User.objects.filter(is_staff=True)

        for staff in us:

            if staff.email:
                logger.info('email task dispatched to staff %s for user %s'
                            % (staff.username, user.username))
                email_user_task.delay(subject, 'user_creation_for_staff',
                                      context, staff)

    def _default_create_user(self, username):
        authMethod = settings.STAGING_PROTOCOL

        authService = AuthService()

        user = authService.getUser(authMethod, username)

        return user

    def process_enclosure(self, dataset, enclosure):
        filename = getattr(enclosure, 'title', basename(enclosure.href))

        # Could check hashes.
        existing_data_files = Dataset_File.objects.filter(filename=filename, dataset=dataset)
        # Set a modification_time if there isn't one there,
        # because if no data file within this data set has
        # a modification time, then is_updated() will assume
        # that the data set needs to be checked for new data
        # files every time it appears in the feed.
        for df in existing_data_files:
            if df.modification_time is None:
                df.modification_time = datetime.now()
                df.save()
        if existing_data_files.count() > 0:
            return

        datafile = Dataset_File(url=enclosure.href, \
                                filename=filename, \
                                dataset=dataset)
        datafile.protocol = enclosure.href.partition('://')[0]
        datafile.created_time = datetime.now()
        datafile.modification_time = datafile.created_time
        try:
            datafile.mimetype = enclosure.mime
        except AttributeError:
            pass
        try:
            datafile.size = enclosure.length
        except AttributeError:
            pass
        try:
            hash = enclosure.hash
            # Split on white space, then ':' to get tuples to feed into dict
            hashdict = dict([s.partition(':')[::2] for s in hash.split()])
            # Set SHA-512 sum
            datafile.sha512sum = hashdict['sha-512']
        except AttributeError:
            pass
        datafile.save()
        self.make_local_copy(datafile)


    def make_local_copy(self, datafile):
        from tardis.tardis_portal.tasks import make_local_copy
        make_local_copy.delay(datafile.id)


    def _get_experiment_details(self, entry, user):
        try:
            # Standard category handling
            experimentId = None
            title = None
            # http://packages.python.org/feedparser/reference-entry-tags.html
            for tag in entry.tags:
                if tag.scheme.endswith(self.PARAM_EXPERIMENT_ID):
                    experimentId = tag.term
                if tag.scheme.endswith(self.PARAM_EXPERIMENT_TITLE):
                    title = tag.term
            if (experimentId != None and title != None):
                return (experimentId, title, Experiment.PUBLIC_ACCESS_NONE)
        except AttributeError:
            pass
        return (user.username+"-default",
                "Uncategorized Data",
                Experiment.PUBLIC_ACCESS_NONE)


    def _get_experiment(self, entry, user):
        experimentId, title, public_access = \
            self._get_experiment_details(entry, user)
        try:
            try:
                param_name = ParameterName.objects.\
                    get(name=self.PARAM_EXPERIMENT_ID, \
                        schema=AtomImportSchemas.get_schema(Schema.EXPERIMENT))
                parameter = ExperimentParameter.objects.\
                    get(name=param_name, string_value=experimentId)
            except ExperimentParameter.DoesNotExist:
                raise Experiment.DoesNotExist
            return parameter.parameterset.experiment
        except Experiment.DoesNotExist:
            experiment = Experiment(title=title,
                                    created_by=user,
                                    public_access=public_access)
            experiment.save()

            if user.first_name or user.last_name:

                author_experiment = Author_Experiment(experiment=experiment,
                                                      author='%s %s' % (user.first_name or '',
                                                                        user.last_name or ''),
                                                      order=0)
                author_experiment.save()

            self._create_experiment_id_parameter_set(experiment, experimentId)
            acl = ExperimentACL(experiment=experiment,
                    pluginId=django_user,
                    entityId=user.id,
                    canRead=True,
                    canWrite=True,
                    canDelete=True,
                    isOwner=True,
                    aclOwnershipType=ExperimentACL.OWNER_OWNED)
            acl.save()
            return experiment

    def _lock_on_schema(self):
        schema = AtomImportSchemas.get_schema()
        Schema.objects.select_for_update().get(id=schema.id)

    def process(self, feed, entry):
        user = self._get_user_from_entry(entry)
        with transaction.commit_on_success():
            # Get lock to prevent concurrent execution
            self._lock_on_schema()
            # Create dataset if necessary
            try:
                dataset = self._get_dataset(feed, entry)

                dataset_latest_modification_time=datetime.fromtimestamp(0)
                for df in Dataset_File.objects.filter(dataset_id=dataset.id):
                    if df.modification_time is None:
                        continue
                    if df.modification_time > dataset_latest_modification_time:
                        dataset_latest_modification_time = df.modification_time

                if iso8601.parse_date(entry.updated) > dataset_latest_modification_time.replace(tzinfo=reference.LocalTimezone()):
                    # Add datafiles
                    for enclosure in getattr(entry, 'enclosures', []):
                        self.process_enclosure(dataset, enclosure)
                    # Set dataset to be immutable
                    dataset.immutable = True
                    dataset.save()

            except Dataset.DoesNotExist:
                experiment = self._get_experiment(entry, user)
                dataset = experiment.datasets.create(description=entry.title)
                logger.debug('Creating new dataset: %s' % entry.title)
                dataset.save()
                # Add metadata for matching dataset to entry in future
                self._create_entry_parameter_set(dataset, entry.id,
                                                 entry.updated)
                # Add datafiles
                for enclosure in getattr(entry, 'enclosures', []):
                    self.process_enclosure(dataset, enclosure)
                # Set dataset to be immutable
                dataset.immutable = True
                dataset.save()
        return dataset



class AtomWalker:


    def __init__(self, root_doc, persister = AtomPersister()):
        self.root_doc = root_doc
        self.persister = persister


    @staticmethod
    def _get_next_href(doc):
        try:
            links = filter(lambda x: x.rel == 'next', doc.feed.links)
            if len(links) < 1:
                return None
            return links[0].href
        except AttributeError:
            # May not have any links to filter
            return None


    def ingest(self):
        for feed, entry in self.get_entries():
            self.persister.process(feed, entry)


    def get_entries(self):
        '''
        returns list of (feed, entry) tuples
        '''
        doc = self.fetch_feed(self.root_doc)
        entries = []
        while True:
            if doc == None:
                break
            new_entries = filter(lambda entry: self.persister.is_new(doc.feed, entry) or self.persister.is_updated(doc.feed, entry), doc.entries)
            entries.extend(map(lambda entry: (doc.feed, entry), new_entries))
            next_href = self._get_next_href(doc)
            # Stop if the filter found an existing entry or no next
            if len(new_entries) != len(doc.entries) or next_href == None:
                break
            doc = self.fetch_feed(next_href)
        return reversed(entries)


    def fetch_feed(self, url):
        logger.debug('Fetching feed: %s' % url)
        return feedparser.parse(url, handlers=[get_credential_handler()])

