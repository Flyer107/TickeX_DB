
#urllib.urlretrieve(dls, "test.xls")
import requests
import csv
import datetime
# mtack : 10,

def get_next_Value(collection, sequence_name, value):
    sequence = collection.find_one_and_update(
        {'_id': sequence_name},
        {'$inc': {'sequence_value': value}})
    return sequence.get('sequence_value')

all_ids = {
            "mbasketball" : { 'num': 5, 'name': "Men's Basketball", 'category' : "Men's" },
            "baseball" : { 'num' : 1, 'name' : "Baseball", 'category' : "Men's"},
            "football": {'num' : 3, 'name' : 'Football', 'category' : "Men's" },
            "mgolf" : { 'num' : 6, 'name' : "Men's Golf", 'category' : "Men's" },
            "mlax" : { 'num' : 7, 'name' : "Men's Lacrosse", 'category' : "Men's" },
            "msoccer" : { 'num' : 8, 'name':"Men's Soccer",'category' : "Men's" },
            "wrestling" : { 'num' : 19, 'name' : "Wrestling",'category' : "Men's" },
            "wbasketball" : { 'num' : 11, 'name' : "Women's Basketball", 'category' : "Women's"},
            "field_hockey":{'num' : 2, 'name' : "Field Hockey", 'category' : "Women's"},
            "wgolf" : {'num': 13, 'name': "Women's Golf", 'category' : "Women's"},
            "wlax" :{'num': 15, 'name': "Women's Lacrosse" , 'category' : "Women's"},
            "wsoccer" : {'num' : 16, 'name' : "Women's Soccer", 'category' : "Women's"},
            "softball" : {'num' : 9, 'name' : "Softball", 'category' : "Women's"},
            "volleyball" : {'num' : 38, 'name' : 'Volleyball', 'category' : "Women's"}
        }

def get_list_from_sport_id( sport_id ):
    url = "https://umterps.com/calendar.ashx/calendar.csv"
    with requests.Session() as s:
        download = s.get(url, headers={'User-Agent': 'Custom'}, params={'sport_id' : sport_id })
        decoded_content = download.content.decode('utf-8')
        cr = csv.reader(decoded_content.splitlines(), delimiter=',')
        my_list = list(cr)
        return my_list

def build_objects( list_of_games ):
    def is_date_after_today(date_string):
        to_date_object = datetime.datetime.strptime(date_string, '%m/%d/%Y')
        return to_date_object > datetime.datetime.now()

    to_return = []
    titles = list_of_games.pop(0)
    for index in range(len(list_of_games)):
        new_obj = {}
        game = list_of_games[index]
        for item in range(len(game)):
            new_obj[ titles[item] ] = game[item]
        start_date = new_obj.get("Start Date")

        if not start_date:
            new_obj["Start Date"] = "TBA"

        if new_obj.get("Start Date") == "TBA" or is_date_after_today(start_date):
            new_obj["Tickets"] = []
            category = new_obj.get("Category")
            if category in new_obj.get("Event"):
                new_obj["Event"] = new_obj.get("Event").replace(category, "UMD")
            description = new_obj.get('Description')
            if category in description:
                new_obj["Description"] = description.replace(category, "UMD")
            to_return.append( new_obj )

    return to_return
def edit_category_and_sport(list_of_games, sport_name, category):
    # iterate over the list of games, accessing by index allows to concurrently modify the list.
    for index in range(len(list_of_games)):
        list_of_games[index]['Sport'] = sport_name
        list_of_games[index]['Category'] = category
    return list_of_games

def parse_schedule( sport ):
    sport_id = sport.get('num')
    category = sport.get("category")
    sport_name = sport.get("name")
    # get the list of games from terps url
    full_schedule = get_list_from_sport_id( sport_id )
    # build objects and parse to only get events that are upcoming
    list_of_games = build_objects( full_schedule )
    # add sport and category to objects
    list_of_games = edit_category_and_sport(list_of_games, sport_name, category)
    return list_of_games

def insert_list_into_collection(mydb, args):
    collection_name = args.get("collection_name")
    collection = mydb[collection_name]
    list_of_items = args.get('list_of_items')
    for item in list_of_items:
        # check to see if the item is already in the collection
        if collection.count_documents(item) == 0:
            item['_id'] = get_next_Value(collection, 'id_values', 1)
            collection.insert_one(item)
    return True
# new_obj["Tickets"] = []
# new_obj["Event"] = new_obj.get("Event").replace(new_obj.get("Category"), "UMD")
# to_return.append( new_obj )
# continue