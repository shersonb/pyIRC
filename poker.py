#!/usr/bin/python
import re
import os
import random
import string
import itertools

spade = '\xe2\x99\xa0'
heart = '\xe2\x99\xa5'
diamond = '\xe2\x99\xa6'
club = '\xe2\x99\xa3'
faces = ["A"]+range(2, 11)+list("JQKA")
suits = [(spade, 1), (club, 1), (heart, 4), (diamond, 4)]
handsmapping = ["High card", "One pair", "Two pair", "Three of a kind", "Straight", "Flush", "Full house", "Four of a kind", "Straight flush", "Royal flush"]


class Game(object):
    def __init__(self):
        self.deck = deck = list(itertools.product(xrange(1, 14), xrange(4)))
        random.shuffle(deck)
        random.shuffle(deck)
        random.shuffle(deck)
        random.shuffle(deck)
        random.shuffle(deck)
        self.status = 0
        self.players = []
        self.hands = {}
        self.waiting = None


class Poker(object):
    def __init__(self):
        self.games = {}

    def onRecv(self, IRC, line, data):
        if data is None:
            return
        (origin, ident, host, cmd, target, params, extinfo) = data
        #print data
        if len(target) and target[0] == "#" and cmd == "PRIVMSG":
            channel = IRC.channel(target)
            user = IRC.user(origin)
            matches = re.findall("^!poker (\\S+)(?:\\s+(.*))?$", extinfo)
            if matches:
                cmd, param = matches[0]
                if cmd == "newgame":
                    if all([m not in channel.modes.keys() or user not in channel.modes[m] for m in "qao"]):
                        channel.msg("%s: You are not operator."%origin)
                    elif channel in self.games.keys():
                        channel.msg("%s: There is already a game going on in this channel."%origin)
                    else:
                        self.games[channel] = Game()
                        channel.msg("A new poker game has started. Type \x02!poker sit\x02 to join.")
                elif cmd == "sit":
                    if channel not in self.games.keys():
                        channel.msg("%s: There is no game going on in this channel."%origin)
                    elif self.games[channel].status != 0:
                        channel.msg("%s: Cannot join the game at this time." %
                                    origin)
                    elif user in self.games[channel].players:
                        channel.msg("%s: You are already in the game."%origin)
                    elif len(self.games[channel].players) >= 8:
                        channel.msg("%s: This game is full."%origin)
                    else:
                        self.games[channel].players.append(user)
                        channel.msg("%s: Welcome to the game."%origin)
                elif cmd == "deal":
                    if all([m not in channel.modes.keys() or user not in channel.modes[m] for m in "qao"]):
                        channel.msg("%s: You are not operator."%origin)
                    elif channel not in self.games.keys():
                        channel.msg("%s: There is no game going on in this channel."%origin)
                    elif len(self.games[channel].players) == 0:
                        channel.msg("%s: Nobody has sat yet."%origin)
                    elif self.games[channel].status > 0:
                        channel.msg("%s: The cards have already been dealt." %
                                    origin)
                    else:
                        channel.me("deals poker hands to %s"%(string.join([user.nick for user in self.games[channel].players], ", ")))
                        P = len(self.games[channel].players)
                        for user in self.games[channel].players:
                            hand = list(self.games[channel].deck[0:5*P:P])
                            del self.games[channel].deck[0:5*P:P]
                            self.games[channel].hands[user] = hand
                            user.notice("Your poker hand is: %s"%(string.join(["\x03%d,0\x02%s%s\x0f"%(suits[s][1], faces[f], suits[s][0]) for (f, s) in hand], ", ")))
                        self.games[channel].status = 1
                        self.games[channel].waiting = self.games[
                            channel].players[0]
                        channel.msg("The cards have been dealt.")
                        channel.msg("%s: Do you wish to draw any cards? Type \x02!poker draw n1,n2,...\x02, where n1,n2,... is a list of cards \x02by index\x02 you wish to draw (0 for first card, 1 for second, etc...). Empty list means you wish to keep all cards."%self.games[channel].waiting.nick)
                elif cmd == "draw":
                    if channel not in self.games.keys():
                        channel.msg("%s: There is no game going on in this channel."%origin)
                    elif user not in self.games[channel].players:
                        channel.msg("%s: You are not in this game."%origin)
                    elif self.games[channel].status != 1:
                        channel.msg("%s: We are not exchanging cards yet." %
                                    origin)
                    elif self.games[channel].waiting != user:
                        channel.msg("%s: It is not your turn to draw cards yet."%origin)
                    else:
                        if param and any([card not in "01234" for card in param.split(",")]):
                            channel.msg("%s: I could not understand your request."%origin)
                        else:
                            if param == "":
                                channel.msg("%s is keeping all cards."%origin)
                                discards = []
                            else:
                                discards = []
                                #print "Param",param
                                for cardid in param.split(","):
                                    card = self.games[channel].hands[user][int(cardid)]
                                    #print "Discarding ",card
                                    if card not in discards:
                                        discards.append(card)
                                for card in discards:
                                    self.games[channel].hands[user].remove(card)
                                channel.msg("%s is exchanging %d card%s."%(origin, len(discards), "s" if len(discards) > 1 else ""))
                                self.games[channel].hands[user].extend(self.games[channel].deck[:len(discards)])
                                del self.games[channel].deck[:len(discards)]
                                self.games[channel].deck.extend(discards)
                                user.notice("Your new poker hand is: %s"%(string.join(["\x03%d,0\x02%s%s\x0f"%(suits[s][1], faces[f], suits[s][0]) for (f, s) in self.games[channel].hands[user]], ", ")))
                                k = self.games[channel].players.index(user)
                                if k < len(self.games[channel].players)-1:
                                    self.games[channel].waiting = self.games[channel].players[k+1]
                                    channel.msg("%s: Do you wish to draw any cards? Type \x02!poker draw n1,n2,...\x02, where n1,n2,... is a list of cards \x02by index\x02 you wish to draw (0 for first card, 1 for second, etc...). Empty list means you wish to keep all cards."%self.games[channel].waiting.nick)
                                else:
                                    self.games[channel].waiting = None
                                    channel.msg("Exchanges done! Waiting for dealer to type \x02!poker show\x02.")
                                    self.games[channel].status = 2
                elif cmd == "show":
                    if all([m not in channel.modes.keys() or user not in channel.modes[m] for m in "qao"]):
                        channel.msg("%s: Access denied."%origin)
                    elif channel not in self.games.keys():
                        channel.msg("%s: There is no game going on in this channel."%origin)
                    elif self.games[channel].status != 2:
                        channel.msg("%s: We are not ready to show cards." %
                                    origin)
                    else:
                        results = []
                        for user in self.games[channel].players:
                            hand = self.games[channel].hands[user]
                            t = evalhand(hand)
                            channel.msg("%s\xe2\x80\x99s poker hand is: %s. A \x02%s\x02."%(user.nick, string.join(["\x03%d,0\x02%s%s\x0f"%(suits[s][1], faces[f], suits[s][0]) for (f, s) in hand], ", "), handsmapping[t[0]]))
                            results.append((t, user))
                        results.sort(reverse=True)
                        top = results[0][0]
                        winners = [user.nick for (t, user)
                                   in results if t == top]
                        if len(winners) > 2:
                            channel.msg("The winners are %s, and %s. A %d-way tie. Well played, gentlemen!"%(string.join(winners[:-1], ", "), winners[-1], len(winners)))
                        elif len(winners) == 2:
                            channel.msg("The winners are %s and %s. A tie. Well played, gentlemen!"%tuple(winners))
                        else:
                            channel.msg("The winner is %s. Well played, gentlemen!"%winners[0])
                        del self.games[channel]
            #matches=re.findall("^!shuffle(?:\\s+([\\d]+))?$",extinfo)
            #if matches:
                #if matches[0]: shuffles=int(matches[0])
                #else: shuffles=1
                #if shuffles>1000:
                    #channel.msg("Get real, %s!"%origin)
                    #return
                #for s in xrange(shuffles): random.shuffle(deck)
                #channel.me("shuffles the deck %d time%s."%(shuffles, "s" if shuffles>1 else ""))


def evalhand(hand):
    facevalues = [face for (face, suit) in hand]
    facevalues.sort(reverse=True)
    suits = [suit for (face, suit) in hand]

    duplicities = [(facevalues.count(k), k) for k in xrange(1, 14)]
    duplicities.sort(reverse=True)
    counts = [count for (count, k) in duplicities]
    faces = [k for (count, k) in duplicities]
    ### Check for flush
    if suits == [0]*5:
        flush = True
    elif suits == [1]*5:
        flush = True
    elif suits == [2]*5:
        flush = True
    elif suits == [3]*5:
        flush = True
    else:
        flush = False

    ### Check for straight
    if (max(counts) == 1 and max(facevalues)-min(facevalues) == 4) or counts == [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]:
        straight = True
    else:
        straight = False

    if flush and not straight:
        return (5,)+tuple(faces)
    elif straight and not flush:
        return (4,)+tuple(faces)
    elif flush and counts == [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1]:
        return (9,)+tuple(faces)
    elif flush and straight:
        return (8,)+tuple(faces)

    if 3 in counts and 2 in counts:
        return (6,)+tuple(faces)

    if 4 in counts:
        return (7,)+tuple(faces)

    if 3 in counts:
        return (3,)+tuple(faces)

    if counts.count(2) == 2:
        return (2,)+tuple(faces)

    if 2 in counts:
        return (1,)+tuple(faces)

    return (0,)+tuple(faces)
