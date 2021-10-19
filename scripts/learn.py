#!/usr/bin/env python

import numpy as np
from tensorflow.keras import layers, Model, utils
import json

def line_count():
    f = open('goodware_uniq.traits', 'r')
    lines = f.readlines()
    f.close()
    return len(lines)

def generator():
    f = open('goodware_uniq.traits', 'r')
    lines = f.readlines()
    for i in range(0, len(lines)):
        data = lines[i].strip().split(' ')
        for j in range(0, len(data)):
            if data[j] == '??':
                data[j] = 256/256
            else:
                data[j] = int(data[j], 16)/256
        print(json.dumps({'features': data}, indent=4))
        yield np.array(data), np.array([(len(data) - data.count(1))/len(data)])
    f.close()

# def generator():
#     while True:
#         length = np.random.randint(2, 10)          # Variable length sequences
#         x_train = np.random.random((1, length, 2)) #batch, seq, features
#         y_train = np.random.random((1,1))          # batch, score
#         yield x_train, y_train

inp = layers.Input((None, 1))
hid = layers.LSTM(10, return_sequences=True)(inp)
hid = layers.LSTM(10)(hid)
out = layers.Dense(1)(hid)

model = Model(inp, out)
model.compile(loss='binary_crossentropy', optimizer='adam')
model.fit(generator(), steps_per_epoch=line_count(), epochs=1, batch_size=1)
