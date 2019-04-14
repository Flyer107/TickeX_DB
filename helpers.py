import json
import requests

if __name__ == '__main__':
    URL = "https://api.sportsdata.io/v3/cfb/scores/json/Games/2019?key=1cac55c0f2374b2d81ac2adf5386cea9"

    print(URL)
    results = requests.get(URL).json()
    print(type(results))

    gameList = []
    for result in results:
        if result.get('HomeTeamName') == 'Maryland Terrapins':
            awayTeam = result.get('AwayTeamName')
            gameDate = result.get('DateTime')
            game_object = {'awayTeam' : awayTeam , 'gameDate' : gameDate , 'gameName' : 'Maryland Terrapins vs. ' + awayTeam}
            print(game_object)
            gameList.append(game_object)

    print(gameList)

if __name__ == '__main__':
    URL="https://api.fantasydata.net/v3/cbb/scores/json/Games/2019?key=8f5e6c8c1f4141ecb5b833850a9484f6"

   
    results = requests.get(URL).json()
    

    gameList = []
    for result in results:
        if result.get('HomeTeam') == 'MARY':
            awayTeam = result.get('AwayTeam')
            gameDate = result.get('DateTime')
            game_object = {'awayTeam' : awayTeam , 'gameDate' : gameDate , 'gameName' : 'Maryland Terrapins vs. ' + str(awayTeam)}
            print(game_object)
            gameList.append(result)

    print(gameList)


def addGametoDB():
    

