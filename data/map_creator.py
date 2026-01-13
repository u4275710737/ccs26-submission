import json
import math
import os

import IP2Location
import PIL
import io
import plotly.express as px
import plotly.graph_objects as go
import pycountry
from tqdm import tqdm
from ipwhois import IPWhois, WhoisRateLimitError, WhoisLookupError, HTTPLookupError, HTTPRateLimitError

DIR_WITH_DATA = "daily_scans"
LIMIT_SINGLE_OUTPUT = ["echo_results_2025-06-27.json"]
WORKING_FILTER = 14
DAY_ANALYSIS = "echo_results_2025-06-27"

def extract_and_parse_information_for_ip(ip_to_analyze, cities_working_parsing_dict, countries_working_parsing_dict, from_date):
    rec = database.get_all(ip_to_analyze)
    city = rec.city
    if city is None or city == "-":
        print("city None or empty! " + str(ip_to_analyze))
        return
    if city not in cities_working_parsing_dict:
        lat = rec.latitude
        lng = rec.longitude
        if lat is None or lng is None:
            print("lat or lng None! " + str(ip_to_analyze))
            return
        cities_working_parsing_dict[city] = [lat, lng, 1, ip_to_analyze]
    else:
        cities_working_parsing_dict[city][2] = cities_working_parsing_dict[city][2] + 1

    country = rec.country_short
    if country is None or country == "-":
        print("country None or empty! " + str(ip_to_analyze))
        return
    if country not in countries_working_parsing_dict:
        # first occurrence for any date
        countries_working_parsing_dict[country] = [rec.country_long, [1], [from_date]]
    else:
        try:
            filename_index = countries_working_parsing_dict[country][2].index(from_date)
            # found for this date --> increase counter
            countries_working_parsing_dict[country][1][filename_index] = countries_working_parsing_dict[country][1][filename_index] + 1

        except ValueError:
            # not present for this date yet
            countries_working_parsing_dict[country][1].append(1)
            countries_working_parsing_dict[country][2].append(from_date)


def create_cities_scatter_plot(cities_working_to_plot, title):
    cities_working_list = []
    lat_working_list = []
    lng_working_list = []
    size_working_list = []
    for key in cities_working_to_plot:
        cities_working_list.append(key)
        dict_object = cities_working_to_plot[key]
        lat_working_list.append(dict_object[0])
        lng_working_list.append(dict_object[1])
        size_working_list.append(dict_object[2])
    scatter_dict = {"lat": lat_working_list, "lng": lng_working_list, "city": cities_working_list, "size": size_working_list}
    fig = px.scatter_geo(scatter_dict, lat="lat", lon="lng", hover_name="city",title=title, size="size", color="size", size_max=40)
    fig.update_layout(font_family="Serif", font_size=20)
    fig.show()

    size_log_working_list = []
    for size in size_working_list:
        size_log_working_list.append(math.log(size))
    scatter_dict = {"lat": lat_working_list, "lng": lng_working_list, "city": cities_working_list, "size_log": size_log_working_list}
    fig = px.scatter_geo(scatter_dict, lat="lat", lon="lng", hover_name="city", title=title, size="size_log", color="size_log", size_max=10)
    fig.update_layout(font_family="Serif", font_size=20)
    fig.show()


def create_countries_choropleth(countries_working_to_plot, title, generate_gif=True):
    countries_working_list_iso2 = []
    countries_long_working_list = []
    countries_size_working_list = []
    countries_date_working_list = []
    for key in countries_working_to_plot:
        for date_index in range(len(countries_working_to_plot[key][1])):
            # extract data point for each date, for each country
            countries_working_list_iso2.append(key)
            dict_object = countries_working_to_plot[key]
            countries_long_working_list.append(dict_object[0])
            countries_size_working_list.append(dict_object[1][date_index])
            countries_date_working_list.append(dict_object[2][date_index])

    countries_working_list = []
    for iso_2 in countries_working_list_iso2:
        countries_working_list.append(pycountry.countries.get(alpha_2=iso_2).alpha_3)
    choropleth_dict = {"country": countries_working_list, "size": countries_size_working_list, "country_long": countries_long_working_list, "date": countries_date_working_list}
    fig = px.choropleth(choropleth_dict, locationmode="ISO-3", locations="country", hover_name="country_long", title=title, color="size", animation_frame="date")
    fig.update_layout(font_family="Serif", font_size=20)
    fig.show()

    countries_size_log_working_list = []
    for size in countries_size_working_list:
        countries_size_log_working_list.append(math.log(size))
    choropleth_dict = {"country": countries_working_list, "size_log": countries_size_log_working_list, "country_long": countries_long_working_list, "date": countries_date_working_list}
    fig = px.choropleth(choropleth_dict, locationmode="ISO-3", locations="country", hover_name="country_long", title=title, color="size_log", animation_frame="date")
    fig.update_layout(font_family="Serif", font_size=20)
    fig.show()

    if generate_gif:
        # generate images for each step in animation
        frames = []
        for s, fr in enumerate(fig.frames):
            # set main traces to appropriate traces within plotly frame
            fig.update(data=fr.data)
            # move slider to correct place
            fig.layout.sliders[0].update(active=s)
            # generate image of current state
            frames.append(PIL.Image.open(io.BytesIO(fig.to_image(format="png"))))

        # create animated GIF
        frames[0].save(
            "animated_heatmap.gif",
            save_all=True,
            append_images=frames[1:],
            optimize=True,
            duration=500,
            loop=0,
        )


def get_common_keys(list_of_dicts):
    if not list_of_dicts:
        return []

    # Get the keys of the first dictionary in the list
    common_keys = set(list_of_dicts[0].keys())

    # Iterate through the remaining dictionaries
    for d in list_of_dicts[1:]:
        # Update common_keys by taking the intersection with keys of current dictionary
        common_keys = common_keys.intersection(d.keys())
        # print(f"Consistent cities with one server over time: {common_keys}")

    return list(common_keys)


database = IP2Location.IP2Location("IP2LOCATION-LITE-DB5.BIN", "SHARED_MEMORY")

countriesWorking = {}
workingIPs = []
workingIPsTCP = []
workingIPsUDP = []
citiesWithOneServer = []

for filename in sorted(os.listdir(DIR_WITH_DATA + "/tcp")):  # loops from oldest to latest
    if filename.count("_") == 3 or not filename.startswith("echo_results"):  # only use daily scans here
        continue

    # extract TCP
    with open(os.path.join(DIR_WITH_DATA + "/tcp", filename), 'r') as f:
        results = json.load(f)

    citiesWorking = {}
    workingIPsDate = []
    workingIPsTCPDate = []
    for result in tqdm(results):
        if result['result'] == "WORKING":
            working_ip = result['echoIP']['address']
            workingIPsTCPDate.append(working_ip)
            workingIPsDate.append(working_ip)
            extract_and_parse_information_for_ip(working_ip, citiesWorking, countriesWorking, filename)
    workingIPsTCP.append(workingIPsTCPDate)

    # extract UDP
    with open(os.path.join(DIR_WITH_DATA + "/udp", filename), 'r') as f:
        results = json.load(f)

    workingIPsUDPDate = []
    for result in tqdm(results):
        if result['result'] == "WORKING":
            working_ip = result['echoIP']['address']
            workingIPsUDPDate.append(working_ip)
            if not working_ip in workingIPsDate:
                workingIPsDate.append(working_ip)
                extract_and_parse_information_for_ip(working_ip, citiesWorking, countriesWorking, filename)
    workingIPsUDP.append(workingIPsUDPDate)

    # extract cities with just one working for each date
    citiesWithOneServerDate = {}
    for city in citiesWorking.keys():
        if (citiesWorking[city][2] == 1):
            citiesWithOneServerDate[city] = citiesWorking[city]
            if city == "Lo So Shing": # most consistent single IP city
                print(f"Behavior of Lo So Shing over time: {citiesWorking[city]}")
    citiesWithOneServer.append(citiesWithOneServerDate
                               )
    workingIPs.append(workingIPsDate)
    print(f"Extracted {len(workingIPsDate)} working Echo servers for date: {filename}")

    if LIMIT_SINGLE_OUTPUT == [] or filename in LIMIT_SINGLE_OUTPUT:
        create_cities_scatter_plot(citiesWorking, "Working Echo Servers Around the World")

create_countries_choropleth(countriesWorking, "Working Echo Servers Around the World", True)

fig = go.Figure()

# create line figure for unique server count
date_count = []
for date in workingIPs:
    date_count.append(len(date))
fig.add_trace(go.Scatter(
    x=list(range(1,len(date_count)+1)), y=date_count,
    mode='lines',
    name='Unique Echo Servers',
    line=dict(color='blue')
))

# create line figure for TCP server count
date_count = []
for date in workingIPsTCP:
    date_count.append(len(date))
fig.add_trace(go.Scatter(
    x=list(range(1,len(date_count)+1)), y=date_count,
    mode='lines',
    name='TCP Echo Servers',
    line=dict(color='yellow')
))

# create line figure for UDP server count
date_count = []
for date in workingIPsUDP:
    date_count.append(len(date))
fig.add_trace(go.Scatter(
    x=list(range(1,len(date_count)+1)), y=date_count,
    mode='lines',
    name='UDP Echo Servers',
    line=dict(color='green')
))

fig.update_layout(font_family="Serif", font_size=20, margin_l=0, margin_r=0, margin_t=0, margin_b=0, plot_bgcolor='white', xaxis_title="Scan Day", yaxis_title="Reachable Echo Servers", yaxis_range=[0, 42000], legend=dict(
        x=0.99,  # push near right edge
        y=0.01,  # push near bottom
        xanchor="right",
        yanchor="bottom",
        bgcolor="rgba(255,255,255,0.7)",  # optional: white with transparency
        bordercolor="black",
        borderwidth=1
    ))
    
fig.update_xaxes(
    mirror=True,
    ticks='outside',
    dtick=2,
    showline=True,
    linecolor='black',
    gridcolor='lightgrey'
)
fig.update_yaxes(
    mirror=True,
    ticks='outside',
    dtick=10000,
    showline=True,
    linecolor='black',
    gridcolor='lightgrey'
)

fig.write_image("server_count.jpeg")
fig.write_html("server_count.html")

consistent_servers_list = []
for date_index in tqdm(range(len(workingIPs))):
    consistent_servers = 0
    for ip in tqdm(workingIPs[0]):
        missing = False
        for date in workingIPs[:date_index+1]:
            if ip not in date:
                missing = True
                break
        if not missing:
            consistent_servers += 1
    consistent_servers_list.append(consistent_servers)
fig = px.line(x=range(1,len(consistent_servers_list)+1), y=consistent_servers_list).update_layout(
    xaxis_title="Scan Day", yaxis_title="Consecutive Reachable Echo Servers", yaxis_range=[0, 42000]
)
fig.update_layout(font_family="Serif", font_size=20, margin_l=0, margin_r=0, margin_t=0, margin_b=0, plot_bgcolor='white')
fig.update_xaxes(
    mirror=True,
    ticks='outside',
    showline=True,
    linecolor='black',
    gridcolor='lightgrey'
)
fig.update_yaxes(
    mirror=True,
    ticks='outside',
    showline=True,
    linecolor='black',
    gridcolor='lightgrey'
)
fig.write_image("consecutive_reachable.jpeg")
fig.write_html("consecutive_reachable.html")

# (Optionally) analyze cities with just one IP over time
# print(f"Consistent cities with one server: {get_common_keys(citiesWithOneServer)}")

print(f"First scan day countries: {len(countriesWorking)}")

# extract working IPs based on threshold
workingIPs = workingIPs[-WORKING_FILTER:]
workingAfterThreshold = []
for ip in workingIPs[0]:
    missing = False
    for date in workingIPs:
        if ip not in date:
            missing = True
            break
    if not missing:
        workingAfterThreshold.append(ip)

print(f"Extracted {len(workingAfterThreshold)} working Echo servers after thresholding")
citiesWorking = {}
countriesWorking = {}
for ip in tqdm(workingAfterThreshold):
    extract_and_parse_information_for_ip(ip, citiesWorking, countriesWorking, f"Consistent {WORKING_FILTER} Days")
create_cities_scatter_plot(citiesWorking, f"Consistent Echo servers for {WORKING_FILTER} days")
create_countries_choropleth(countriesWorking, f"Consistent Echo servers for {WORKING_FILTER} days", False)

# single day analysis
hourlyWorkingIPs = []
for filename in sorted(os.listdir(DIR_WITH_DATA + "/tcp")):  # loops from oldest to latest
    if not filename.startswith(DAY_ANALYSIS):
        continue

    # TCP
    with open(os.path.join(DIR_WITH_DATA + "/tcp", filename), 'r') as f:
        results = json.load(f)

    workingIPs = []
    for result in tqdm(results):
        if result['result'] == "WORKING":
            working_ip = result['echoIP']['address']
            workingIPs.append(working_ip)

    # UDP
    if os.path.exists(os.path.join(DIR_WITH_DATA + "/udp", filename)):
        with open(os.path.join(DIR_WITH_DATA + "/udp", filename), 'r') as f:
            results = json.load(f)

        for result in tqdm(results):
            if result['result'] == "WORKING":
                working_ip = result['echoIP']['address']
                if working_ip in workingIPs:
                    continue
                workingIPs.append(working_ip)
    else:
        workingIPs = []
        continue

    hourlyWorkingIPs.append(workingIPs)

matches = set()
counts = []
if hourlyWorkingIPs != []:
    for i in range(len(hourlyWorkingIPs)):
        #print(len(hourlyWorkingIPs[i]))
        if i == 0:
            matches = set(hourlyWorkingIPs[i])
        else:
            matches = matches.intersection(hourlyWorkingIPs[i])
        counts.append(len(matches))
    fig = px.line(x=range(len(counts)), y=counts).update_layout(
        xaxis_title="Hour After Initial Scan", yaxis_title="Consecutive Reachable Echo Servers", yaxis_range=[0, 42000]
    )
    fig.update_layout(font_family="Serif", font_size=20, margin_l=0, margin_r=0, margin_t=0, margin_b=0,
                      plot_bgcolor='white')
    fig.update_xaxes(
        mirror=True,
        ticks='outside',
        showline=True,
        linecolor='black',
        gridcolor='lightgrey'
    )
    fig.update_yaxes(
        mirror=True,
        ticks='outside',
        showline=True,
        linecolor='black',
        gridcolor='lightgrey'
    )
    fig.write_image("hourly_analysis.jpeg")
    fig.write_html("hourly_analysis.html")
