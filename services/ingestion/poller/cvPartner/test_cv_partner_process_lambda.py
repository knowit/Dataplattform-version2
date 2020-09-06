from cv_partner_process_lambda import handler
from dataplattform.common import schema
from pytest import fixture
from os import path
from json import load
import pandas as pd


@fixture
def test_data():
    with open(path.join(path.dirname(__file__), 'test_data.json'), 'r') as json_file:
        yield load(json_file)


@fixture
def setup_queue_event(s3_bucket):
    def make_queue_event(data: schema.Data):
        s3_bucket.Object('/data/test.json').put(
            Body=data.to_json().encode('utf-8'))
        return {
            'Records': [{
                'body': '/data/test.json',
                'messageAttributes': {
                    's3FileName': {
                        'stringValue': '/data/test.json'
                    }
                }
            }]
        }
    yield make_queue_event


def test_initial_process(setup_queue_event, test_data, create_table_mock):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)
    create_table_mock.assert_table_created(
        'employee_data',
        'education_data',
        'blogs_data',
        'courses_data',
        'key_qualification_data',
        'languages_data',
        'project_experience_data',
        'technology_skills_data',
        'work_experience_data')


def test_process_table_content(setup_queue_event, test_data, create_table_mock):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'employee_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_2'],
            'default_cv_id': ['user_id_1_cv_id', 'user_id_2_cv_id'],
            'image': ["image1", "image2"],
            'link': ["link1", "link2"],
            'navn': ['Test Testerson', 'Test Testerson 2'],
            'email': ["test@test.no", "test@test2.no"],
            'telefon': ['+123456', '+123456'],
            'born_year': [1995, 1985],
            'nationality': ["Norwegian", "Swedish"],
            'place_of_residence': ['Oslo', 'Oslo'],
            'twitter': [pd.NA, "twitter2"]
        }))


def test_process_table_content_missing_born_date(setup_queue_event, test_data, create_table_mock):

    tmp_data = test_data['data']
    tmp_data[0]['cv'].pop('born_year', None)

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=tmp_data))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'employee_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_2'],
            'default_cv_id': ['user_id_1_cv_id', 'user_id_2_cv_id'],
            'image': ["image1", "image2"],
            'link': ["link1", "link2"],
            'navn': ['Test Testerson', 'Test Testerson 2'],
            'email': ["test@test.no", "test@test2.no"],
            'telefon': ['+123456', '+123456'],
            'born_year': [pd.NA, 1985],
            'nationality': ["Norwegian", "Swedish"],
            'place_of_residence': ['Oslo', 'Oslo'],
            'twitter': [pd.NA, "twitter2"]
        }))


def test_process_education_table_content(setup_queue_event, test_data, create_table_mock):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'education_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_1', 'user_id_2', 'user_id_2'],
            'degree': ['Bachelor1', 'Master1', 'Bachelor2', 'Master2'],
            'month_from': ["08", "08", "08", "08"],
            'month_to': ["05", "06", "05", "06"],
            'year_from': ["2014", "2017", "2014", "2017"],
            'year_to': ["2019", "2019", "2019", "2019"],
            'time_from': ["08/2014", "08/2017", "08/2014", "08/2017"],
            'time_to': ["05/2019", "06/2019", "05/2019", "06/2019"]
            }))


"""
Case: user1 has no education
"""


def test_process_education_table_content_missing(setup_queue_event, test_data,
                                                 create_table_mock):

    tmp_data = test_data['data']
    tmp_data[0]['cv'].pop('educations', None)

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=tmp_data))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'education_data',
        pd.DataFrame({
            'user_id': ['user_id_2', 'user_id_2'],
            'degree': ['Bachelor2', 'Master2'],
            'month_from': ["08", "08"],
            'month_to': ["05", "06"],
            'year_from': ["2014", "2017"],
            'year_to': ["2019", "2019"]
            }))


def test_project_experiences_df(setup_queue_event, test_data, create_table_mock):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'project_experience_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_1', 'user_id_2', 'user_id_2'],
            'customer': ['costumer1', 'costumer2', 'costumer3', 'Knowit Objectnet'],
            'month_from': ["01", "06", "08", "12"],
            'year_from': ["2015", "2017", "2019", "2019"],
            'project_experience_skills': ["HTML/CSS;Github", "Angular;npm", "Yarn;VS Code", "AWS DynamoDB;Github"],
            'roles': ["Fullstackutvikler",
                      "Frontendutvikler",
                      "Frontendutvikler;Brukeranalyse;DevOps-utvikler",
                      "Backendutvikler"]
            }))


"""
Case: project skills not defined for a project
"""


def test_project_experiences_df_project_skills_missing(setup_queue_event, test_data, create_table_mock):
    tmp_data = test_data['data']
    tmp_data[0]['cv']['project_experiences'][1].pop('project_experience_skills', None)

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=tmp_data))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'project_experience_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_1', 'user_id_2', 'user_id_2'],
            'customer': ['costumer1', 'costumer2', 'costumer3', 'Knowit Objectnet'],
            'month_from': ["01", "06", "08", "12"],
            'year_from': ["2015", "2017", "2019", "2019"],
            'project_experience_skills': ["HTML/CSS;Github", "", "Yarn;VS Code", "AWS DynamoDB;Github"],
            'roles': ["Fullstackutvikler",
                      "Frontendutvikler",
                      "Frontendutvikler;Brukeranalyse;DevOps-utvikler",
                      "Backendutvikler"]
            }))


"""
Case: costumer not defined for a project
"""


def test_project_experiences_df_costumer_missing(setup_queue_event, test_data, create_table_mock):
    tmp_data = test_data['data']
    tmp_data[0]['cv']['project_experiences'][0].pop('customer', None)

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=tmp_data))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'project_experience_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_1', 'user_id_2', 'user_id_2'],
            'customer': ['', 'costumer2', 'costumer3', 'Knowit Objectnet'],
            'month_from': ["01", "06", "08", "12"],
            'year_from': ["2015", "2017", "2019", "2019"],
            'project_experience_skills': ["HTML/CSS;Github", "Angular;npm", "Yarn;VS Code", "AWS DynamoDB;Github"],
            'roles': ["Fullstackutvikler",
                      "Frontendutvikler",
                      "Frontendutvikler;Brukeranalyse;DevOps-utvikler",
                      "Backendutvikler"]
            }))


"""
Test replace missing values with pd.NA
"""


def test_work_experiences_df_missing(setup_queue_event, test_data,
                                     create_table_mock):

    tmp_data = test_data['data']
    tmp_data[1]['cv']['work_experiences'][0].pop('month_from', None)

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=tmp_data))

    handler(event, None)
    create_table_mock.assert_table_data_contains_df(
        'work_experience_data',
        pd.DataFrame({
            'user_id': ['user_id_1', 'user_id_1', 'user_id_1', 'user_id_2', 'user_id_2', 'user_id_2'],
            'month_from': ["06", "06", "08", pd.NA, "06", "08"],
            }))
