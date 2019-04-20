import json
import requests
from passlib.apps import custom_app_context as pwd_context
from flask import redirect, session, url_for


class AppMethods:
    def __init__(self):
        pass
        # nothing to do

    def login_manager(self, username, password, mycollection):
        # try to find the user in the data base by username
        result_username = mycollection.find_one({'username': username})

        if len(list(result_username)) < 1:

            result_username = mycollection.find_one({'email': username})

        if len(list(result_username)) < 1:
            return redirect(url_for('index'))

        if result_username.get('activated') == 'False':
            return redirect(url_for('index'))

        if not pwd_context.verify(password + result_username.get('salt'), result_username.get('password')):
            return redirect(url_for('index'))

        session['username'] = result_username.get('username')

        session['user_id'] = result_username.get('_id')
        return redirect(url_for('index'))


"""
# get url with data for the football information
URL = "https://api.sportsdata.io/v3/cfb/scores/json/Games/2019?key=1cac55c0f2374b2d81ac2adf5386cea9"
print(URL)
results = requests.get(URL).json()  # turn that data into a json format
print(type(results))

gameList = []  # store the list of games in this
for result in results:  # loop throught the results
# if the home team name matches UMD's
if result.get('HomeTeamName') == 'Maryland Terrapins':
    # get the naem of the away team
    awayTeam = result.get('AwayTeamName')
    gameDate = result.get('DateTime')  # get the date of the game
    game_object = {'Sport': 'Football', 'awayTeam': awayTeam, 'gameDate': gameDate,
                    'gameName': 'Maryland Terrapins vs. ' + awayTeam}  # store all that information into a dictionary
    print(game_object)

# get the basketball information with the url
URL = "https://api.fantasydata.net/v3/cbb/scores/json/Games/2019?key=8f5e6c8c1f4141ecb5b833850a9484f6"
# again transform that data into a json file format
results = requests.get(URL).json()
for result in results:
if result.get('HomeTeam') == 'MARY':
    awayTeam = result.get('AwayTeam')
    gameDate = result.get('DateTime')
    # convert all that data into a dictionary to be stored into the database
    game_object = {'Sport': 'Basketball', 'awayTeam': awayTeam,
                    'gameDate': gameDate, 'gameName': 'Maryland Terrapins vs. ' + str(awayTeam)}
    print(game_object)

def main():
    URL = "https://api.sportsdata.io/v3/cfb/scores/json/Games/2019?key=1cac55c0f2374b2d81ac2adf5386cea9"

print(URL)
results = requests.get(URL).json()
print(type(results))

gameList = []
for result in results:
    if result.get('HomeTeamName') == 'Maryland Terrapins':
        awayTeam = result.get('AwayTeamName')
        gameDate = result.get('DateTime')
        game_object = {'Sport': 'Football', 'awayTeam': awayTeam,
                        'gameDate': gameDate, 'gameName': 'Maryland Terrapins vs. ' + awayTeam}
        gameList.append(game_object)

URL = "https://api.fantasydata.net/v3/cbb/scores/json/Games/2019?key=8f5e6c8c1f4141ecb5b833850a9484f6"

results = requests.get(URL).json()

for result in results:
    if result.get('HomeTeam') == 'MARY':
        awayTeam = result.get('AwayTeam')
        gameDate = result.get('DateTime')
        game_object = {'Sport': 'Basketball', 'awayTeam': awayTeam,
                        'gameDate': gameDate, 'gameName': 'Maryland Terrapins vs. ' + str(awayTeam)}
        gameList.append(game_object)
"""
