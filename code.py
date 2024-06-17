import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

df = pd.read_csv("mqttdataset_reduced.csv")
df = df[(df["target"] == "legitimate") | (df["target"] == "dos")]
df["target"].unique()

scaler = MinMaxScaler(feature_range=(0, 1))
numerical_features = df.columns[df.dtypes != 'object']
if len(numerical_features) > 0:
    df[numerical_features] = scaler.fit_transform(df[numerical_features])
label_encoder = LabelEncoder()
df['tcp.flags'] = label_encoder.fit_transform(df['tcp.flags'])
df = df.replace(["0", "0x00000000"], 0)
df['mqtt.conflags'] = df['mqtt.conflags'].astype(str)
df['mqtt.conflags'] = label_encoder.fit_transform(df['mqtt.conflags'])
df['mqtt.hdrflags'] = df['mqtt.hdrflags'].astype(str)
df['mqtt.hdrflags'] = label_encoder.fit_transform(df['mqtt.hdrflags'])
df['mqtt.msg'] = df['mqtt.msg'].astype(str)
df["msg_len"] = [len(val) for val in df["mqtt.msg"].to_list()]
df = df.drop('mqtt.msg', axis=1)
df['mqtt.protoname'] = df['mqtt.protoname'].astype(str)
df['mqtt.protoname'] = label_encoder.fit_transform(df['mqtt.protoname'])
label_encoder.fit(["legitimate", "dos"])
mapping = {"legitimate": 0, "dos": 1}
df["target"] = [mapping[label] for label in df["target"].to_list()]

x = df.drop('target', axis=1)
y = df["target"]
feature_names = [
    'mqtt.hdrflags',
    'msg_len',
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
features = {}
for i in feature_names:
    features[i] = x[i]
features = pd.DataFrame(features)

clf = DecisionTreeClassifier(splitter="random")
clf.fit(x, y)

import streamlit as st
st.title("ML based IDS for IoT")
st.text("Enter the below details to find if the packet is a part of an DOS attack or not: ")

input = {}
for i in feature_names:
    input[i] = st.text_input(i)

if st.button("Submit"):
    inputs=[[]]
    for i in range(len(input)):
        inputs[0][i] = input[i]
    result = clf.predict(inputs)
    if result == 0:
        val = "Legitimate Packet"
    else:
        val = "DoS Attack Related Packet" 