# -*- coding: utf-8 -*-
"""
Created on Thu Nov  8 16:16:09 2018

@author: jakez
"""
import os

def getKeys():
    if 'MONGO_STRING' not in os.environ:
        dotenv = '.env.ini'
        with open(dotenv, 'r') as file:
            content = file.readlines()

        content = [line.strip().split('=') for line in content if '=' in line]
        env_vars = dict(content)
        if file:
            file.close()
        return env_vars
    else:
        return_dict = {}
        to_return = ['MONGO_STRING', 'MONGO_USER', 'MONGO_USER_PW', 'USER_DB', 'VERIFY_EMAIL_DB',
        'GAMES_DB', 'ERROR_DB', 'DB_NAME', 'FOLDER_NAME', 'EMAIL_ADDRESS', 'EMAIL_PASSWORD']
        for item in to_return:
            return_dict[item] = os.environ.get(item)

        return return_dict
settings = getKeys()
#    os.environ.update({"SECRET_KEY" : })