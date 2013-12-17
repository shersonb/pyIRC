#!/usr/bin/python
import os
import re
import time


class TempConvertionBot(object):
    def __init__(self, expiry=1800):
        self.__name__ = "TempConversion Bot"
        self.__version__ = "0.0.1"
        self.pattern = re.compile(r"([-+]?\d+|[-+]?\d*\.\d+)\s*(?:degrees?)?\s*(C|F)(?=\s|$)")

    def onChanMsg(self, IRC, user, channel, targetprefix, msg):
        matches = self.pattern.findall(msg)
        for quantity, unit in matches:
            quantity = float(quantity)
            if unit == 'C':
                quantityPrime = quantity * 9 / 5.0 + 32
                unitPrime = 'F'

            elif unit == 'F':
                quantityPrime = (quantity - 32) * 5 / 9.0
                unitPrime = 'C'

            channel.me("notes that %0.2f %s is %0.2f %s" % (quantity, unit, quantityPrime, unitPrime))
