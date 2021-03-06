from pytest import fixture
from ubw_customer_per_resource_process_lambda import handler
import pandas as pd
from os import path
from json import load
from dataplattform.common import schema


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


def test_process_data(create_table_mock, setup_queue_event, test_data, dynamodb_resource):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)

    create_table_mock.assert_table_data_column(
        'ubw_customer_per_resource',
        'reg_period',
        pd.Series(['202053', '202053', '202053']))


def test_process_data_test_weigth(create_table_mock, setup_queue_event, test_data, dynamodb_resource):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)

    create_table_mock.assert_table_data_column(
        'ubw_customer_per_resource',
        'weigth',
        pd.Series([1, 2, 1]))

    create_table_mock.assert_table_data_column(
        'ubw_customer_per_resource',
        'customer',
        pd.Series(['customer 2', 'customer 1', 'customer 3']))


def test_process_data_test_used_hrs_zero(create_table_mock, setup_queue_event, test_data, dynamodb_resource):
    test_data['data'][0]['used_hrs'] = 0

    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)

    create_table_mock.assert_table_data_column(
        'ubw_customer_per_resource',
        'weigth',
        pd.Series([1, 1]))

    create_table_mock.assert_table_data_column(
        'ubw_customer_per_resource',
        'customer',
        pd.Series(['customer 2', 'customer 3']))


def test_process_data_test_dataframe_content(create_table_mock, setup_queue_event, test_data, dynamodb_resource):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=0),
            data=test_data['data']))

    handler(event, None)

    create_table_mock.assert_table_data(
        'ubw_customer_per_resource',
        pd.DataFrame({
            'reg_period': ['202053', '202053', '202053'],
            'alias': ['pernord', 'pernord', 'karnord'],
            'project_type': ['External Projects', 'Local Projects', 'Local Projects'],
            'work_order': ['work order no 2', 'work order no 1', 'work order no 3'],
            'work_order_description': ['Some work order desc.', 'Some work order desc.', 'Some work order desc.'],
            'customer': ['customer 2', 'customer 1', 'customer 3'],
            'time': [0, 0, 0],
            'weigth': [1, 2, 1],
            'guid': ['20dbbfa18380233aa643575720b893fac5137699',
                     '20dbbfa18380233aa643575720b893fac5137699',
                     '491b9fa9bfac17563882b0fdc6f3a8a97417bd99'],
        }))


def test_process_per_project_data_content(create_table_mock, setup_queue_event, test_data, dynamodb_resource):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=1601294392),
            data=test_data['data']))

    handler(event, None)
    create_table_mock.assert_table_data(
        'ubw_per_project_data',
        pd.DataFrame({
            'customer': ['customer 2', 'customer 1', 'customer 3'],
            'employees': [1, 1, 1],
            'hours': [6.0, 4.0, 1.0],
            'reg_period': ["202053", "202053", "202053"],
            'timestamp': [1601294392, 1601294392, 1601294392]
        }))


def test_process_only_appending_historical_data(s3_bucket, setup_queue_event, test_data, dynamodb_resource):
    event = setup_queue_event(
        schema.Data(
            metadata=schema.Metadata(timestamp=1601294392),
            data=test_data['data']))

    handler(event, None)
    handler(event, None)

    keys_in_s3 = [x.key for x in s3_bucket.objects.all() if 'structured' in x.key]
    expected_keys = [
        'data/test/structured/ubw_customer_per_resource/_common_metadata',
        'data/test/structured/ubw_customer_per_resource/_metadata',
        'data/test/structured/ubw_customer_per_resource/part.0.parquet',
        'data/test/structured/ubw_per_project_data/_common_metadata',
        'data/test/structured/ubw_per_project_data/_metadata',
        'data/test/structured/ubw_per_project_data/part.0.parquet',
        'data/test/structured/ubw_per_project_data/part.1.parquet'
    ]
    assert len(expected_keys) == len(keys_in_s3)
    assert all([keys_in_s3[i] == expected_keys[i] for i in range(len(keys_in_s3))])
