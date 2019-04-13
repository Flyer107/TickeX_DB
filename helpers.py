import json
import requests

if __name__ == '__main__':
    URL = "https://api.sportradar.us/ncaamb-t3/games/2013/REG/schedule.json?api_key={}".format(
        'xkm2uutsdjkez85myk7u946r')

    print(URL)
    result = requests.get(URL)
    with open('results.txt', 'w+') as file:
        file.write(str(result.json()))
