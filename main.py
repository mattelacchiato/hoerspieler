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
    KEY = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    def __init__(self):
        self._create()

    def wait_for_tag(self):
        self.rdr.wait_for_tag()

    def _prepare_request(self):
        """Returns (error, uid)"""
        try:
            (error, tag_type) = self.rdr.request()
            if error: return (error, None)
            (error, uid) = self.rdr.anticoll()
            if error: return (error, None)
            print("Found card UID: " + str(uid))
            return (self.rdr.select_tag(uid), uid)
        except:
            self.rdr.stop_crypto()

    def read_ndef_bytes(self):
        """Returns bytes or raises exception"""
        def get_length(block):
            if block[4] == bytes([0]):
                raise Exception("ndef record longer than 256 bytes. Please implement =)")
            else:
                return block[4]
        
        def read_block(block_address):
            (error, read) = self.rdr.read(block_address)
            if error: 
                raise Exception("failed to read block %s" % block_address)
            else:
                return bytes(read)

        
        (error, uid) = self._prepare_request()
        if error: raise Exception("failed to prepare request")

        error = self.rdr.card_auth(self.rdr.auth_b, 4, self.KEY, uid)
        if error: raise Exception("failed to auth sector 1")
        
        start_block = 4
        read = read_block(start_block)
        # ndef records starts with this sequence:
        print("#########################")
        print(str(read))

        if read[:3] != bytes([0, 0, 3]):
            raise Exception("Start block with invalid starting sequence: %s" % read)
        length = get_length(read)
        bytes_to_read = length
        print("Found NDEF with %s length" % length)
        ndef_bytes = read[start_block:(start_block+bytes_to_read)]
        bytes_to_read -= 16-start_block
        for i in range(start_block+1, 63):
            if bytes_to_read <= 0:
                break
            elif i % 4 == 3:
                #ignore every 4th blocks (reserved for key mgmt), but auth for next sector
                error = self.rdr.card_auth(self.rdr.auth_b, i+1, self.KEY, uid)
                if error: raise Exception("failed to auth sector %s" % i/4)
                continue
            else:
                ndef_bytes += read_block(i)[:bytes_to_read]
                bytes_to_read -= 16
        print("found ndef bytes: %s" % str(ndef_bytes))
        if length != len(ndef_bytes):
            self._recreate()
            raise Exception("Could not read all NDEF bytes (Declared: %i, got: %i)" % (length, len(ndef_bytes)))
        return ndef_bytes

    def write_ndef(self, record_bytes):
        def zpad(list, count):
            """padds with zeros to the end"""
            return (list + bytes(count))[:count]

        block_address = 4
        length = len(record_bytes)
        octets = bytes([0, 0, 3, length]) + record_bytes + b'\xFE'
        (error, uid) = self._prepare_request()
        if error: raise Exception("failed to prepare request")

        try:
            while len(octets) > 0:
                if (block_address) % 4 == 0:
                    #do auth for next sector
                    error = self.rdr.card_auth(self.rdr.auth_b, block_address+1, self.KEY, uid)
                    if error: raise Exception("failed to auth sector 1")
                else:
                    block = zpad(octets, 16)
                    print("writing on block %i: %s" % (block_address, str(block)))
                    self.rdr.write(block_address, block)
                    octets = octets[16:]
                block_address += 1
        except:
            self.rdr.stop_crypto()

    def _create(self):
        self.rdr = RFID()
        self.util = self.rdr.util()
        self.util.debug = True
        self.util.auth(self.rdr.auth_b, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    #todo: check if needed (_prepare before each request should do the trick)
    def _recreate(self):
        self._reset()
        self._create()

    def _reset(self):
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
    silently(lambda _:wrapper._reset())
    sys.exit()

""" def read_out(block_address):
    #todo wtf?
    if not wrapper.util.is_tag_set_auth():
        return True

    error = wrapper.util.do_auth(block_address)
    if not error:
        (error, data) = wrapper.rdr.read(block_address)
        return bytes(data)
    else:
        raise Exception("Error on " + wrapper.util.sector_string(block_address))
 """
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

def write2(rdr, block_address, data):
    """
    Writes data to block. You should be authenticated before calling write.
    Returns error state.
    """
    buf = []
    buf.append(rdr.act_write)
    buf.append(block_address)
    crc = rdr.calculate_crc(buf)
    buf.append(crc[0])
    buf.append(crc[1])
    (error, back_data, back_length) = rdr.card_write(rdr.mode_transrec, buf)
    if not(back_length == 4) or not((back_data[0] & 0x0F) == 0x0A):
        print("fail1")
        error = True

    if not error:
        buf_w = []
        for i in range(16):
            buf_w.append(data[i])

        crc = rdr.calculate_crc(buf_w)
        buf_w.append(crc[0])
        buf_w.append(crc[1])
        (error, back_data, back_length) = rdr.card_write(rdr.mode_transrec, buf_w)
        if not(back_length == 4) or not((back_data[0] & 0x0F) == 0x0A):
            error = True
            print("fail2")

    return error


def write_ndef(block_address, records):
    def zpad(list, count):
        """padds with zeros to the end"""
        return (list + bytes(count))[:count]

    record_bytes = b''.join((ndef.message_encoder(records)))
    length = len(record_bytes)
    octets = bytes([0, 0, 3, length]) + record_bytes + b'\xFE'
    while len(octets) > 0:
        if (block_address) % 4 != 3:
            block = zpad(octets, 16)
            print("writing on block %i: %s" % (block_address, str(block)))
            if wrapper.util.do_auth(block_address):
                print("Error while auth.")
            if write2(wrapper.rdr, block_address, block):
                print("Error while writing.")
            octets = octets[16:]
        block_address += 1

def parse_records(octets):
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

        try:
            print("Wait for tag")
            wrapper.wait_for_tag()

            ndef_bytes = wrapper.read_ndef_bytes()
            records = parse_records(ndef_bytes)
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
                        record_bytes = b''.join((ndef.message_encoder(records)))
                        wrapper.write_ndef(record_bytes)
                    elif current_track != records[1].uri:
                        print("replacing " + str(records[1].uri))
                        records[1] = current_track_rec
                        record_bytes = b''.join((ndef.message_encoder(records)))
                        wrapper.write_ndef(record_bytes)
                except BaseException as e:
                    # non-fatal here. simply print for debugging
                    traceback.print_exc(file=sys.stdout)
            print("Tag removed")
            sp.pause_playback(device_id)
            time.sleep(1)
        except BaseException as e:
            print("Ignoring Exception")
            traceback.print_exc(file=sys.stdout)
        finally:
            wrapper._recreate()
except BaseException as e:
    traceback.print_exc(file=sys.stdout)
finally:
    cleanup()
