import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

df = pd.read_csv("preprocessed.csv")

x = df.drop('target', axis=1)
y = df["target"]

feature_names = [
    'mqtt.hdrflags',
    'mqtt.msg',
    'mqtt.msgid',
    'mqtt.len',
    'tcp.flags',
    'mqtt.kalive',
    'mqtt.conflag.cleansess',
    'mqtt.willmsg_len',
    'mqtt.qos',
    'tcp.time_delta',
    'mqtt.dupflag',
    'mqtt.willtopic',
    'mqtt.conflags',
    'mqtt.protoname',
    'tcp.len',
    'mqtt.msgtype',
    'mqtt.proto_len',
    'mqtt.ver'
]

clf = DecisionTreeClassifier(splitter="random")
clf.fit(x, y)

import streamlit as st
st.title("ML based IDS for IoT")
st.text("Enter the below details to find if the packet is a part of an DOS attack or not: ")

file = st.file_uploader(label="Upload pcap file for analysis: ", type="pcap")





# if st.button("Submit"):
#     inputs=[[]]
#     for i in range(len(input)):
#         inputs[0][i] = input[i]
#     result = clf.predict(inputs)
#     if result == 0:
#         val = "Legitimate Packet"
#     else:
#         val = "DoS Attack Related Packet" 
