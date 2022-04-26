from django.test.utils import override_settings
from dojo.models import Finding_Group, User, Finding, Test, JIRA_Instance, JIRA_Issue, Development_Environment, Engagement, JIRA_Project
from dojo.jira_link import helper as jira_helper
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient
from jira.exceptions import JIRAError
from .dojo_test_case import DojoVCRAPITestCase, get_unit_tests_path
from crum import impersonate
from django.utils import timezone
# from unittest import skip
import logging
from vcr import VCR
from django.db import transaction
from dojo.forms import JIRAEngagementForm
from django.urls import reverse
from django.utils.http import urlencode
from django.test.client import Client


logger = logging.getLogger(__name__)

# logger.setLevel(logging.DEBUG)

# jira_link_logger = logging.getLogger('dojo.jira_link.helper')
# jira_link_logger.setLevel(logging.DEBUG)

# forms_logger = logging.getLogger('dojo.forms')
# forms_logger.setLevel(logging.DEBUG)

# these tests are using vcrpy to record traffic to and from JIRA: https://vcrpy.readthedocs.io/en/latest/usage.html
# after being recorded, the traffic is used for future runs of the tests
# this allows us to locally develop tests, run them, make them work against a real JIRA instance.
# after that we can commit the tests AND the recordings (cassettes).

# the record_mode is set to 'once' by default. this means it will replay responses from the cassette, if there is a cassette.
# otherwise it will create a new cassette and record responses. on the next run the cassette wil be used.

# if changing tests, you can best remove all cassettes before running the tests.
# or you can temporarily set the record_mode to all the make it always go to the real JIRA and record all the traffic.

# when the tests are finished, you'll have to set the assertCassettePlayed method to make it assert
# that all entries in the cassette have been used by the test.

# if you need some credentials for the Defect Dojo JIRA Cloud instance, contact one of the moderators

# some senstive data is filtered out by the filter_headers config option below
# as well as some custom callback functions to filter out cookies.
# please check the recorded files on sensitive data before committing to git


class JIRAParentIssueLinkingTestApi(DojoVCRAPITestCase):
    fixtures = ['dojo_testdata.json']

    # product_id = 999

    def __init__(self, *args, **kwargs):
        # TODO remove __init__ if it does nothing...
        DojoVCRAPITestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super(JIRAParentIssueLinkingTestApi, self)._get_vcr(**kwargs)
        my_vcr.record_mode = 'once'
        my_vcr.path_transformer = VCR.ensure_suffix('.yaml')
        my_vcr.filter_headers = ['Authorization', 'X-Atlassian-Token']
        my_vcr.cassette_library_dir = get_unit_tests_path() + '/vcr/jira/'
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def toggle_jira_project_parent_issue_linking (self, obj, value):
        project = jira_helper.get_jira_project(obj)
        project.enable_parent_issue_linking = value
        project.project_key = self.jira_project.project_key
        project.save()

    def create_parent_issue(self):
        fields = {
                'project': {
                    'key': self.jira_project.project_key
                },
                'summary': "Parent Issue for Finding Jira Issues",
                'description': "Parent Issue for Finding Jira Issues",
                'issuetype': {
                    'name': 'Epic'
                },
        }

        new_issue = self.jira.create_issue(fields)
        self.parent_issue = new_issue
        logger.debug (f"parent j_issue {self.parent_issue}")

        with transaction.atomic(): 
            j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
            # update parent issue jira issue for the engagement
            logger.debug (f"before updating for parent j_issue value - {j_issue}")
            j_issue.jira_id = self.parent_issue.id
            j_issue.jira_key = self.parent_issue.key
            # j_issue.jira_creation = timezone.now()
            # j_issue.jira_change = timezone.now()
            j_issue.save()
            logger.debug (f"updated value for parent j_issue {JIRA_Issue.objects.get(engagement=self.eng_id)}")

    # @transaction.atomic
    # def set_parent_issue_in_engagement(self):        
    #     j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
    #     # update parent issue jira issue for the engagement
    #     logger.debug (f"before updating for parent j_issue value - {j_issue}")
    #     j_issue.jira_id = self.parent_issue.id
    #     j_issue.jira_key = self.parent_issue.key
    #     # j_issue.jira_creation = timezone.now()
    #     # j_issue.jira_change = timezone.now()
    #     j_issue.save()
    #     logger.debug (f"updated value for parent j_issue {JIRA_Issue.objects.get(engagement=self.eng_id)}")

    @transaction.atomic
    def create_jira_issue(self, finding):
        logger.debug("create_jira_issue")

        fields = {
                'project': {
                    'key': self.jira_project.project_key
                },
                'summary': finding.title,
                'description': finding.title,
                'issuetype': {
                    'name': self.jira_instance.default_issue_type
                },
        }

        new_issue = self.jira.create_issue(fields)

        j_issue = JIRA_Issue.objects.filter(finding=finding.id)
        logger.debug (f"Jira issue: before updating j_issue value - {j_issue}")

        if j_issue:
            j_issue = JIRA_Issue.objects.get(finding=finding.id)
            j_issue.jira_id = new_issue.id
            j_issue.jira_key = new_issue.key
            # j_issue.jira_creation = timezone.now()
            # j_issue.jira_change = timezone.now()
        else:
            j_issue = JIRA_Issue(
                    jira_id=new_issue.id, jira_key=new_issue.key, jira_project=self.jira_project)
            j_issue.set_obj(finding)
            # j_issue.save()

        j_issue.save()
        logger.debug(f"issues updated with {JIRA_Issue.objects.filter(finding=finding.id)}")
        self.jira_issues.append(new_issue)

        try:
            # update finding value
            finding.jira_issue = j_issue
            finding.has_jira_issue = True
            finding.save()
        except:
            pass

    def setUp(self):
        super().setUp()

        # get details from fixture
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        self.user.usercontactinfo.block_execution = True
        self.user.usercontactinfo.save()

        # login to DD
        token = Token.objects.get(user=self.user)
        self.client = APIClient(raise_request_exception=True)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
        
        self.client_ui = Client()
        self.client_ui.force_login(self.user)

        self.product_id = 1
        # engagement id 1 is selected which has test id 3 and related findings
        self.eng_id = 1
        # engagement details
        self.eng = self.get_engagement(self.eng_id)
        self.test = Test.objects.filter(engagement=self.eng)

        # configure Jira setting
        self.system_settings(enable_jira=True)
        self.jira_issues = []

        # Connect to jira to get the new issue
        self.jira_instance = jira_helper.get_jira_instance(self.eng)
        logger.debug(f"jira_instance.username {self.jira_instance.username}")

        self.jira = jira_helper.get_jira_connection(self.jira_instance)
        self.jira_project = jira_helper.get_jira_project(self.eng)

        # this needs to be set in the fixture
        self.jira_project.project_key = 'SEA'
        # jira_project.project_key = new_issue.key
        # jira_project.save()
        self.create_parent_issue()

    def create_jira_issue_for_findings(self):
        # get all the finding related to the engagement
        findings = Finding.objects.filter(test__engagement=self.eng_id)

        # create Jira issue for the findings
        for finding in findings:
            logger.debug(f"finding data {finding.title}")
            self.create_jira_issue(finding)
    
    # @transaction.atomic
    def tearDown(self):
        super().tearDown()
        logger.debug("teardown called after every test case")
    
        try:
            self.parent_issue.delete() if self.parent_issue else False
        except JIRAError as e:
            logger.warning("error deleting issue")

        # delete finding jira issue
        for jira_issue in self.jira_issues:
            try:
                issue=self.jira.issue(jira_issue)
                issue.delete()
            except JIRAError as e:
                logger.warning("error deleting issue")

        self.parent_issue = ''
        self.jira_issues = []
        
        # remove parent jira issue configuration
        with transaction.atomic():
            j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
            j_issue.jira_key = ''
            j_issue.jira_key = ''
            j_issue.save()

    class requestForm:
        def __init__(self, product_id, parent_issue_key):
            self.POST = {
                'name': 'engagement with parent Jira issue',
                'description': 'engagement with parent Jira issue',
                'lead': 1,
                'product': product_id,
                'target_start': '2022-11-27',
                'target_end': '2023-12-04',
                'status': 'Not Started',
                # 'jira-project-form-inherit_from_product': 'on', # absence = False in html forms
                'jira-project-form-jira_instance': 2,
                'jira-project-form-project_key': 'SEA',
                'jira-project-form-product_jira_sla_notification': 'on',
                'jira-epic-form-jira_parent_issue': parent_issue_key
            }

    def test_add_jira_issue(self):
        logger.info("test_add_jira_issue")
        # # create jira issues for findings
        # self.create_jira_issue_for_findings()

        self.toggle_jira_project_parent_issue_linking(self.eng, True)

        # create parent issue separately
        # self.set_parent_issue_in_engagement()
        
        issues_in_parent = None
        self.jira_issues = []
        skip_finding = []

        findings = Finding.objects.filter(test__engagement=self.eng_id)

        # first create jira issue for findings
        for obj in findings:
            # JIRA_Issue.objects.filter(finding__in=test.finding_set.all())
            j_issue = JIRA_Issue.objects.filter(finding=obj.id)
            if j_issue:
                logger.debug(f"jira_issue already exists for {obj} with details {j_issue}")
                skip_finding.append(obj.id)
            else:
                logger.debug(f"no jira issue with finding {obj}, so adding jira issue")
                # make sure findings are active and verified
                with transaction.atomic():
                    obj.active = True
                    obj.verified = True
                    obj.save()
                if jira_helper.add_jira_issue(obj):
                    logger.debug(f"successfully created jira issue for finding {obj}")
                else:
                    logger.debug(f"not able to create jira issue for finding {obj}")

        # now use the parent issue in engagement can be used to search Jira to get the issue
        try:
            issues_in_parent = self.jira.search_issues(f"parent={self.parent_issue.key}")
            logger.debug(f"issues list with parent {self.parent_issue} - {issues_in_parent}")
        except JIRAError as e:
            logger.warning("error searching issues having parent issue")
       
        # findings is already updated to remove the finding obj that already has j_issue
        # findings = Finding.objects.filter(test__engagement=self.eng_id)

        for obj in findings:
            # JIRA_Issue.objects.filter(finding__in=test.finding_set.all())
            if obj.id in skip_finding:
                logger.debug(f"skipping finding {obj}")
            else:
                j_issue = JIRA_Issue.objects.get(finding=obj.id)
                logger.debug(f"jira_issue after updating {j_issue}")
                self.jira_issues.append(j_issue.jira_key)
        
        # list of jira issue with key and id
        if issues_in_parent:
            # making sure every issue associated with finding is in the parent issue list returned
            for jira_issue in issues_in_parent:
                self.assertTrue(jira_issue.key in self.jira_issues)

            # delete issues created and unset issues in finding
            # self.tearDown()
        else:
            logger.debug("error getting issue with parent set, test failed")

        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    # def test_update_jira_issue(self):
        # update_jira_issue - only updates existing jira issue's details or updates parent
        # so first add jira issues for findings with parent not configured. then enable parent linking and update to verify
        # parent is updated


    def test_add_issue_to_parent(self):
        logger.info("test_add_issue_to_parent")
        # create jira issues for findings directly using jira python sdk
        self.create_jira_issue_for_findings()

        # create parent issue separately
        # self.set_parent_issue_in_engagement()
        
        issues_in_parent = None
        self.jira_issues = []

        findings = Finding.objects.filter(test__engagement=self.eng_id)

        for obj in findings:
            # JIRA_Issue.objects.filter(finding__in=test.finding_set.all())
            j_issue = JIRA_Issue.objects.get(finding=obj.id)
            logger.debug(f"test finding j_issue {j_issue} {obj}")

            try:
                issue = self.jira.issue(j_issue.jira_key)
                if jira_helper.add_issue_to_parent(obj, self.jira_project, issue):
                    logger.debug("successfully updated parent issue")
                    self.jira_issues.append(issue.key)
                else:
                    logger.debug(f"not able to update jira for {j_issue.jira_key}")
            except:
                # there is one finding that is not updated
                pass

        # now use the parent issue in engagement can be used to search Jira to get the issue
        try:
            issues_in_parent = self.jira.search_issues(f"parent={self.parent_issue.key}")
            logger.debug(f"issues list with parent {self.parent_issue} - {issues_in_parent}")
        except JIRAError as e:
            logger.warning("error searching issues having parent issue")
       
        # list of jira issue with key and id
        if issues_in_parent:
            # making sure every issue associated with finding is in the parent issue list returned
            for jira_issue in issues_in_parent:
                self.assertTrue(jira_issue.key in self.jira_issues)
                    
            # delete issues created and unset issues in finding
            # self.delete_jira_issues()

        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()

    def test_add_issue_to_parent_without_parent_issue(self):
        logger.info("test_add_issue_to_parent_without_parent_issue")

        j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
        with transaction.atomic():
            # make sure j_issue doesn't have any parent issue
            j_issue.jira_key = ''
            j_issue.jira_key = ''
            j_issue.save()

        # create jira issues directly using jira python sdk
        self.create_jira_issue_for_findings()
        self.jira_issues = []

        findings = Finding.objects.filter(test__engagement=self.eng_id)
        for obj in findings:
            # JIRA_Issue.objects.filter(finding__in=test.finding_set.all())
            j_issue = JIRA_Issue.objects.get(finding=obj.id)
            logger.debug(f"test finding j_issue {j_issue} {obj}")

            try:
                issue = self.jira.issue(j_issue.jira_key)
                if jira_helper.add_issue_to_parent(obj, self.jira_project, issue):
                    logger.debug("successfully updated without parent issue")
                    self.jira_issues.append(issue.key)
                else:
                    logger.debug(f"not able to update jira for {j_issue.jira_key}")
            except:
                # there is one finding that is not updated
                pass

        # currently there is no straigh forward way to check parent issue for a jira issue.
        # so make sure jira info stored is valid
        for obj in findings:
            j_issue = JIRA_Issue.objects.get(finding=obj.id)
            self.assertTrue(j_issue.jira_key in self.jira_issues)
        
        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played()    

    # # def test_bulk_findings_push_to_jira(self):

    # # test helper function used for processing Jira epic form
    def test_helper_process_jira_form_parent_issue(self):
        logger.info("test_helper_process_jira_form_parent_issue")

        logger.debug(f"before jira epic form {JIRA_Issue.objects.get(engagement=self.eng_id)}")

        if jira_helper.process_jira_form_parent_issue(self.eng, self.parent_issue.key):
            logger.debug("return true from process_jira_form_parent_issue")

        # check whether the jira issue is updated?
        j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
        # update parent issue jira issue for the engagement
        logger.debug(f"after jira epic form {JIRA_Issue.objects.get(engagement=self.eng_id)}")

        self.assertEqual(j_issue.jira_id, self.parent_issue.id)
        self.assertEqual(j_issue.jira_key, self.parent_issue.key)

        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played() 

    # test for process_jira_epic_form
    def test_process_jira_epic_form(self):
        logger.info("test_helper_process_jira_form_parent_issue")
        if jira_helper.process_jira_epic_form(self.requestForm(self.product_id, self.parent_issue.key), self.eng):
            logger.debug("return true from process_jira_epic_form")

        # check whether the jira issue is updated?
        j_issue = JIRA_Issue.objects.get(engagement=self.eng_id)
        # update parent issue jira issue for the engagement
        logger.debug(f"after jira epic form {JIRA_Issue.objects.get(engagement=self.eng_id)}")

        self.assertEqual(j_issue.jira_id, self.parent_issue.id)
        self.assertEqual(j_issue.jira_key, self.parent_issue.key)

        # by asserting full cassette is played we know issues have been updated in JIRA
        self.assert_cassette_played() 

    # def test_process_jira_epic_form_without_parent_issue(self):
    #   self.parent_issue = ''
    #   self.edit_engagement_jira(self.get_new_engagement_with_jira_project_data(self.parent_issue)
