#!/usr/bin/env python

import signal
import time
import sys
import os
import traceback
import json

#import requests
#from requests_toolbelt.utils import dump

import ndef
import spotipy
import spotipy.util as spotipy_util
from pirc522 import RFID

#ToDo: rm if not needed
class NeedsResetException(Exception):
    def __init__(self, module):
        self.module = module
    pass

class RFIDWrapper:
    def __init__(self):
        self.create()

    def create(self):
        self.rdr = RFID()
        self.util = self.rdr.util()
        self.util.debug = False

    def recreate(self):
        self.reset()
        self.create()

    def reset(self):
        self.util.deauth()
        self.rdr.cleanup()

        

def end_read(signal, frame):
    print("\nCtrl+C captured, ending read.")
    cleanup()

def silently(lam):
    try:
        lam("")
    except BaseException as e:
        print("Got silenced Exception: "+e)


def cleanup():
    silently(lambda _:sp.pause_playback(device_id))
    global run
    run = False
    wrapper.reset()
    sys.exit()

def read_out(block_address):
    if not wrapper.util.is_tag_set_auth():
        return True

    error = wrapper.util.do_auth(block_address)
    if not error:
        (error, data) = wrapper.util.rfid.read(block_address)
        return bytes(data)
    else:
        raise Exception("Error on " + wrapper.util.sector_string(block_address))

# todo: read once

def is_tag_present():
    rdr = wrapper.rdr
    rdr.init()
    rdr.irq.clear()
    rdr.dev_write(0x04, 0x00)
    rdr.dev_write(0x02, 0xA0)

    rdr.dev_write(0x09, 0x26)
    rdr.dev_write(0x01, 0x0C)
    rdr.dev_write(0x0D, 0x87)
    present = rdr.irq.wait(0.1)
    rdr.irq.clear()
    rdr.init()
    return present

def read_ndef(block_address):
    def get_length(block):
        if block[4] == bytes([0]):
            raise Exception("ndef record longer than 256 bytes. Please implement =)")
        else:
            return block[4]

    read = read_out(block_address)
    # ndef records starts with this sequence:
    print("#########################")
    print(str(read))
    if read[:3] == bytes([0, 0, 3]):
        length = get_length(read)
        bytes_to_read = length
        print("Found NDEF with %s length" % length)
        # todo check if necessary
        ndef_bytes = read[4:(4+bytes_to_read)]
        bytes_to_read -= 16-4
        for i in range(block_address+1, 63):
            if bytes_to_read <= 0:
                break
            elif i % 4 == 3:
                #ignore every 4th blocks (reserved for key mgmt)
                continue
            else:
                ndef_bytes += read_out(i)[:bytes_to_read]
                bytes_to_read -= 16
        print("found ndef bytes: %s" % str(ndef_bytes))
        if length != len(ndef_bytes):
            wrapper.recreate()
            raise Exception("Could not read all NDEF bytes (Declared: %i, got: %i)" % (length, len(ndef_bytes)))
        return ndef_bytes


def spotify_client():
    scope = 'user-modify-playback-state,user-read-playback-state'
    username = os.environ['USERNAME']
    client_id = os.environ['CLIENT_ID']
    client_secret = os.environ['CLIENT_SECRET']
    token = spotipy_util.prompt_for_user_token(username, scope, client_id, client_secret, "http://google.de")

    if not token:
        raise Exception("can't get token for " + username)
    return spotipy.Spotify(auth=token)


def get_device_id(sp):
    # todo repeat until found
    for device in sp.devices()["devices"]:
        print(str(device))
        if device["name"].startswith("raspotify"):
            return device["id"]
        else:
            continue

def write_ndef(block_address, records):
    def zpad(list, count):
        return (list + bytes(count))[:count]

    record_bytes = b''.join((ndef.message_encoder(records)))
    length = len(record_bytes)
    octets = bytes([0, 0, 3, length]) + record_bytes + b'\xFE'
    while len(octets) > 0:
        if (block_address) % 4 != 3:
            block = zpad(octets, 16)
            print("writing on block %i: %s" % (block_address, str(block)))
            wrapper.util.do_auth(block_address)
            if wrapper.rdr.write(block_address, block):
                print("Error while writing.")
            octets = octets[16:]
        block_address += 1

def read_records():
    octets = read_ndef(4)
    records = list(ndef.message_decoder(octets))
    if records[0].type != "urn:nfc:wkt:U":
        raise Exception("Only URI records are supported. Was: "+str(records[0]))
    elif not records[0].uri.startswith("https://open.spotify.com"):
        raise Exception("Currently, only spotify links are supported. Was: "+str(records[0]))
    else:
        return records


def prepareOnce():
    signal.signal(signal.SIGINT, end_read)
    print("Starting")
    global sp, device_id, run
    
    run = True
    sp = None
    device_id = None
    while sp == None:
        try:
            sp = spotify_client()
        except BaseException:
            traceback.print_exc(file=sys.stdout)
    while device_id == None:
        try:
            device_id = get_device_id(sp)
        except BaseException:
            traceback.print_exc(file=sys.stdout)


try:
    prepareOnce()
    wrapper = RFIDWrapper()
    while run:
        print("Running")
        #cleanup_rfid()

        try:
            (error, data) = wrapper.rdr.request()
            if not error:
                print("\nDetected: " + format(data, "02x"))

            (error, uid) = wrapper.rdr.anticoll()
            if not error:
                wrapper.util.set_tag(uid)
                wrapper.util.auth(wrapper.rdr.auth_b, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                # for i in range(0,63):
                #    read_out(i)
                records = read_records()
                print(records[0].uri)
                offset = {"uri": records[1].uri} if len(records) > 1 else None
                sp.start_playback(device_id=device_id, context_uri=records[0].uri, offset=offset)
                while is_tag_present():
                    print("Tag is present")
                    try:
                        time.sleep(1)
                        currently_playing = sp.currently_playing()
                        current_track = currently_playing["item"]["uri"]
                        print("current track: "+str(current_track))
                        current_track_rec = ndef.UriRecord(current_track)
                        if len(records) < 2:
                            print("appending.")
                            records.append(current_track_rec)
                            write_ndef(4, records)
                        elif current_track != records[1].uri:
                            print("replacing " + str(records[1].uri))
                            records[1] = current_track_rec
                            write_ndef(4, records)
                    except BaseException as e:
                        # non-fatal here. simply print for debugging
                        traceback.print_exc(file=sys.stdout)
                print("Tag removed")
                sp.pause_playback(device_id)
            time.sleep(1)
        except BaseException as e:
            print("Ignoring Exception")
            traceback.print_exc(file=sys.stdout)
except BaseException as e:
    traceback.print_exc(file=sys.stdout)
finally:
    cleanup()
