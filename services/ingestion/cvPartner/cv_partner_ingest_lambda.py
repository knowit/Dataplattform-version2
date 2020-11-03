from dataplattform.common.handlers.ingest import IngestHandler
from dataplattform.common.helper import save_document
from dataplattform.common.aws import SSM
from dataplattform.common.schema import Data, Metadata
from datetime import datetime
import requests
from uuid import uuid4

url = 'https://knowit.cvpartner.com/api/v3'
url_v1 = 'https://knowit.cvpartner.com/api/v1'
offset_size = 1000
handler = IngestHandler()


@handler.ingest()
def ingest(event) -> Data:

    objectnet_id = SSM(with_decryption=False).get('cv_partner_objectnet_id')
    sor_id = SSM(with_decryption=False).get('cv_partner_sor_id')
    api_token = SSM(with_decryption=True).get('cv_partner_api_token')

    res = requests.get(f'{url}/search?office_ids[]={objectnet_id}&office_ids[]={sor_id}&offset=0&size={offset_size}',
                       headers={'Authorization': f'Bearer {api_token}'})

    data_json = res.json()

    def download_private_cv_doc(person, filename, language: str = 'no', ext: str = 'pdf'):
        http_request = {'requestUrl': get_cv_link(person['cv']['user_id'],
                                                  person['cv']['id'], language=language, ext=ext),
                        'filename': f'private/{filename}',
                        'filetype': f'{ext}',
                        'header': {'Authorization': f'Bearer {api_token}'},
                        'private': True
                        }

        return save_document(http_request)

    def download_public_image(person, filename, ext: str = 'jpg'):
        http_request = {'requestUrl': person['cv']['image']['thumb']['url'],
                        'filename': f'public/{filename}',
                        'filetype': f'{ext}',
                        'private': False
                        }

        return save_document(http_request)

    def write_cv_doc_to_private_bucket(person, language: str = 'no', ext: str = 'pdf'):
        new_key = f'cv_{language}_{ext}'
        filename = f'{uuid4()}.{ext}'
        key = download_private_cv_doc(person, filename, language, ext)
        return {new_key: key}

    def write_cv_image_to_public_bucket(person, ext: str = 'jpg'):
        new_key = 'image_key'
        filename = f'{uuid4()}.{ext}'
        key = download_public_image(person, filename, ext)
        return {new_key: key}

    def get_cv_link(user_id, cv_id, language: str = 'no', ext: str = 'pdf'):
        return url_v1 + f"/cvs/download/{user_id}/{cv_id}/{language}/{ext}/"

    def get_person(person):
        d = {
            'user_id': person['cv']['user_id'],
            'default_cv_id': person['cv']['id'],
            'cv_link': url_v1 + f"/cvs/download/{person['cv']['user_id']}/{person['cv']['id']}/{{LANG}}/{{FORMAT}}/"
        }

        d.update(write_cv_image_to_public_bucket(person))
        d.update(write_cv_doc_to_private_bucket(person, language='no', ext='pdf'))
        d.update(write_cv_doc_to_private_bucket(person, language='int', ext='pdf'))
        d.update(write_cv_doc_to_private_bucket(person, language='no', ext='docx'))
        d.update(write_cv_doc_to_private_bucket(person, language='int', ext='docx'))

        return d

    def get_cv(user_id, cv_id):
        cv = requests.get(url + f'/cvs/{user_id}/{cv_id}',
                          headers={'Authorization': f'Bearer {api_token}'})
        return cv.json()

    def get_list_of_users(data):
        list_of_users = []
        for person in data['cvs']:
            user = get_person(person)
            user['cv'] = get_cv(user['user_id'], user['default_cv_id'])
            list_of_users.append(user)
        return list_of_users

    return Data(metadata=Metadata(timestamp=datetime.now().timestamp()), data=get_list_of_users(data_json))
