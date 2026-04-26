import json
from settings import configuration

def main():
    with open('logs/full_extraction_data_with_validations.json', mode='r', encoding='utf-8') as file:
        full_data = json.load(file)
       