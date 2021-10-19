#!/usr/bin/env python

import logging
import math
import numpy as np
import json
import argparse
import tensorflow as tf

tf.get_logger().setLevel('WARNING')

def sigmoid(x):
  return 1 / (1 + math.exp(-x))

def fitness(data):
    return sigmoid((len(data) - data.count(1)) * len(data))

def line_count():
    f = open('goodware_uniq.traits', 'r')
    lines = f.readlines()
    f.close()
    return len(lines)

def generator(goodware_traits, malware_traits, threshold):
    f = open(malware_traits, 'r')
    lines = f.readlines()
    steps = 0
    for i in range(0, len(lines)):
        data = lines[i].strip().split(' ')
        for j in range(0, len(data)):
            if data[j] == '??':
                data[j] = 256/256
            else:
                data[j] = int(data[j], 16)/256
        if fitness(data) >= threshold:
            yield np.array(data), np.array([1])
    f.close()
    f = open(goodware_traits, 'r')
    lines = f.readlines()
    steps = 0
    for i in range(0, len(lines)):
        data = lines[i].strip().split(' ')
        for j in range(0, len(data)):
            if data[j] == '??':
                data[j] = 256/256
            else:
                data[j] = int(data[j], 16)/256
        if fitness(data) >= threshold:
            yield np.array(data), np.array([0])
    f.close()

def calculate_steps(traits, threshold):
    f = open(traits, 'r')
    lines = f.readlines()
    steps = 0
    for i in range(0, len(lines)):
        data = lines[i].strip().split(' ')
        for j in range(0, len(data)):
            if data[j] == '??':
                data[j] = 256/256
            else:
                data[j] = int(data[j], 16)/256
        if fitness(data) >= threshold:
            steps = steps + 1
    f.close()
    return steps

fitness_const = 0.99999999
optimizer = tf.keras.optimizers.Adam(lr = 1e-3, decay = 1e-5)

print('[-] calculating epoc steps...')
steps = calculate_steps('goodware_uniq.traits', fitness_const) + calculate_steps('out.traits', fitness_const)
print('[*] {steps} steps with fitness of {fitness}'.format(steps=steps, fitness=fitness_const))

print('[-] setting up neural net layers..')
inp = tf.keras.layers.Input((None, 1))
hid = tf.keras.layers.LSTM(10, return_sequences=True)(inp)
hid = tf.keras.layers.Dropout(0.2)(hid)
hid = tf.keras.layers.LSTM(10)(hid)
hid = tf.keras.layers.Dropout(0.2)(hid)
out = tf.keras.layers.Dense(1)(hid)
print('[-] neural net layers setup completed')

print('[-] setting up model')
model = tf.keras.Model(inp, out)
model.compile(loss='binary_crossentropy', optimizer=optimizer, metrics=['accuracy'])
model.summary()
print('[*] model setup completed')
print('[-] training model')
model.fit(generator('out.traits', 'goodware_uniq.traits', fitness_const), steps_per_epoch=steps, epochs=1, batch_size=1)
model.save('malware.class')
print('[*] model training completed')
