#! /usr/bin/env python3

"""
SM server tester.

`./sm_test.py`
"""

import socket
import time
import traceback
import struct
import select
import enum
import sys
from searcher import Searcher


"""
Each messages are repetition of (FIELD_KEY, BODY_LEN, BODY)'s.

- FIELD_KEY = 12-byte null-terminated UTF-8 string
- BODY_LEN = 4-byte integer
- BODY = any payload that has size of BODY_LEN bytes


SEARCH Message Protocol

| Field Key      | Type   | Len  | Body                                  |
|----------------|--------|------|---------------------------------------|
| SEARCH         | String | ?    | Search body                           |
| DATA-TYPE      | Int    | 4    | 101 (wav) 102 (fingerprint)           |
| DATA           | Binary | ?    | Fingerprint data                      |
| TOGGLE         | Int[2] | 8    | nToggleMin, nToggleMax                |
| LIMIT          | Int    | 4    | maximum number of found songs         |
| FULL-SEARCH    | Int    | 4    | non-zero (enable), 0 (disable)        |
| FPBLK-SIZE     | Int    | 4    | fingerpirnt block size                |
| BER-TH         | Double | 8    | BER threshold                         |
| BER-FR-TH      | Double | 8    | BER fast return threshold             |
| QUERY-ID       | I / S  | 4/?  | Query ID - can be Int or String       |

*Note : SEARCH, DATA-TYPE, DATA are mandatory


RESPONSE Message Protocol

| Field Key      | Type   | Len  | Body                                  |
|----------------|--------|------|---------------------------------------|
| RESPONSE       | String | ?    | Response body                         |
| STATUS-CODE    | Int    | 4    | Status code (see below)               |
| SONG           | String | ?    | Song body - optional (see below)      |

SONG body

| Field Key      | Type   | Len  | Body                                  |
|----------------|--------|------|---------------------------------------|
| SONG-ID        | Int    | 4    | SongID (track_id)                     |
| BER            | Double | 8    | Bit error rate                        |
| OFFSET         | Int    | 4    | Matched offset                        |
| OFFSET-TIME    | Int    | 4    | Matched offset time (millisec)        |
| TOGGLE         | Int    | 4    | Bit toggle number when matched        |
| ARTIST         | String | ?    | Artist name                           |
| TITLE          | String | ?    | Song Title                            |
| ALBUM          | String | ?    | Album Name                            |


STATUS CODES

- 200: OK
- 400: bad request - failed to parse message / invalid message
- 404: not found - search failure
- 412: precondition failure
- 430: too short query
- 431: fingerprint extraction failure
- 500: internal server error
- 503: service unavailable - cannot connect to match engine
- 504: service timeout
"""

# parameters
DATA_TYPE_FINGERPRINT = 102
MAX_TOGGLE = 3

# message block related
FIELD_KEY_SIZE = 12
BODY_LEN_SIZE = 4
MESSAGE_HEADER_SIZE = FIELD_KEY_SIZE + BODY_LEN_SIZE


# error messages from error codes
ERROR_MESSAGE = {
    '200': 'OK',
    '400': 'Bad Request - failed to parse message / invalid message',
    '404': 'Not Found - search failure',
    '412': 'Precondition Failure',
    '430': 'Too short query',
    '431': 'Fingerprint Extraction Failure',
    '500': 'Internal Server Error',
    '503': 'Service Unavailable - Cannot connect to Match Engines',
    '504': 'Service Timeout',
}


@enum.unique
class WritePhase(enum.Enum):
    """Write phase"""
    SENDING = 1
    DONE = 2


@enum.unique
class ReadPhase(enum.Enum):
    """Read phase"""
    RESPONSE_HEADER = 1
    STATUS_CODE = 2
    SONGHEADER = 3
    SONGBODY = 4
    DONE = 5


class SmSearcher(Searcher):
    """
    Session manager tester.
    """
    def __init__(self, host: str, port):
       # super().__init__(host, port)

        self.sock = None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host,port))
        sock.setblocking(0)  # set to non-blocking mode
        self.sock = sock
        self.write_phase = ('write_pcm', 'done')	
        self.available_bodytype = ['s', 'd', 'ii', 'i']
        self.number_size = {
            'd': 8,  # double
            'ii': 8,  # two integers
            'i': 4  # integer
        }
        self.read_phase = ReadPhase.RESPONSE_HEADER
        self.write_phase = WritePhase.SENDING

    def make_message_block(self, key: str, body_type: str, body):
        """
        Creates a message block consisting FIELD_KEY, BODY_LEN, and BODY.

        Args:
            key (str): field key name
            body_type (str): symbol conforming 'struct pack'
            body (str | bytes): payload

        Returns:
            message (bytes): message payload consisting all components
        """
        # check whether body types are available
        if body_type not in self.available_bodytype:
            raise ValueError('Invalid type of body:{}. Should be in: {}'
                             .format(body_type, self.available_bodytype))

        # if the body type has non-fixed size, we need to prepend the size
        if body_type == 's':
            if type(body) != bytes:
                body = bytes(body, 'utf-8')
            body_size = len(body)
            # ex) '104s'
            body_signature = '{}{}'.format(body_size, body_type)
        else:
            body_size = self.number_size[body_type]
            body_signature = body_type

        # encode string to bytes, as protocol requires
        if isinstance(key, str):
            key = bytes(key, 'utf-8')

        # '!' = pack in network byte-order
        # '12si' = length 12 byte string + 4-byte integer
        header = struct.pack('!12si', key, body_size)
        body_format = '!{}'.format(body_signature)
        # in case of 'TOGGLE' message,
        # two integers have to be unpacked and passed on separately
        if body_type == 'ii':
            message_body = struct.pack(body_format, *body)
        else:
            message_body = struct.pack(body_format, body)
        return header + message_body

    def read_block_header(self, socket, expected_key=None, expected_val_len=None):
        """
        Reads block header (FIELD_KEY and BODY_LEN) from remote server.

        Args:
            socket: socket
            expected_key (str|None): the field key that the reader expects
            expected_val_len (int|None): the value length that reader expects

        Returns:
            key (str): the field key
            val_len (int): value length

        Raises:
            ValueError: if the retrieved key is different from expected key
            ValueError: if the retrieved value length is different from expected
        """
        key, _ = self.read_string(
            sock=socket, expected_len=12, strip_null_char=True)
        if expected_key is not None and key != expected_key:
            raise ValueError(
                'Key field different. exptected: {}, received: {}.'
                .format(expected_key, key))

        # read the length of value and compare
        val_len = self.read_int(sock=socket)
        if expected_val_len is not None and val_len != expected_val_len:
            raise ValueError(
                'Value lenth different than expected : {}. Received {}.'
                .format(expected_val_len, val_len))
        return key, val_len

    def read_block_value(self, socket, expected_key: str, val_type: str):
        """
        Reads block value.

        Args:
            socket: socket
            expected_key (str|None): the field key that the reader expects
            val_type (str): symbol for type of value conforming to 'struct.pack'

        Returns:
            value: the value that this message contained
            message_len: the total size of this message
        """
        # different value length according to type
        if val_type == 'i':
            expected_val_len = 4
        elif val_type == 'ii' or val_type == 'd':
            expected_val_len = 8

        # read the header first
        _, val_len = self.read_block_header(socket, expected_key, expected_val_len)

        # read the value
        if val_type == 'i':
            value = self.read_int(sock=socket)
        if val_type == 'ii':
            val1 = self.read_int(sock=socket)
            val2 = self.read_int(sock=socket)
            value = (val1, val2)
        if val_type == 'd':
            value = self.read_double(sock=socket)
        return value, (val_len + MESSAGE_HEADER_SIZE)

    @staticmethod
    def handle_status_code(status_code: int):
        """
        Determine whether a status code is successful,
        and return appropriate message.

        Args:
            status_code (int): status code received from SM

        Returns:
            success (bool): True if successful
            msg (str): accompanying status message
        """
        success = False
        if status_code == 200:
            success = True
        return success, ERROR_MESSAGE[str(status_code)]

    def make_payload(self, data: bytes):
        """
        Creates a query message payload to send to SM server.

        Args:
            data (bytes): fingerprint data to send

        Returns:
            search_message (bytes): search message payload
        """
        # prepare components of message
        data_type = self.make_message_block(
            'DATA-TYPE', body_type='i', body=DATA_TYPE_FINGERPRINT)
        toggle = self.make_message_block(
            'TOGGLE', body_type='ii', body=(0, MAX_TOGGLE))
        query_id = self.make_message_block(
            'QUERY-ID', body_type='s', body='AudioplatformTester')
        body = self.make_message_block(
            'DATA', body_type='s', body=data)
        search_message_data = data_type + body + toggle + query_id

        # final message packed to send
        search_message = self.make_message_block(
            'SEARCH', body_type='s', body=search_message_data)
        return search_message

    def search(self, fp: bytes, send_bytes: int=1024):
        """
        Given a fingerprint, search the contents to
        SessionManager servers directly.

        Args:
            fp (bytes): fingerprint data
            send_bytes (int): number of bytes to send per write
                [WARNING] connection error may occur if this value is too large

        Returns:
            status_code (int): result status code
            returned_songs (list[dict]): list of song informations
            msg (str): result message
        """
        # create query message payload
        search_message = self.make_payload(data=fp)

        # set up sockets to read and write
        in_socks, out_socks, xlists = [self.sock], [self.sock], []

        # keep some constants to keep within the loop
        response_body_len = 0  # keep track of remaining response body size
        status_code = -1
        song_body_len = 0
        #returned_songs = []
        done = False
        msg = ''
        while True:
            readable, writable, _ = select.select(in_socks, out_socks, xlists, 10)

            ### WRITING
            for ws in writable:
                if self.write_phase == WritePhase.SENDING:
                    if len(search_message) >= send_bytes:
                        to_send = send_bytes
                    else:
                        to_send = len(search_message)
                    sent = ws.send(search_message[:to_send])
                    search_message = search_message[sent:]
                else:
                    out_socks.clear()  # clear sockets from output list
                    self.write_phase = WritePhase.DONE

            ### READING
            for rs in readable:
                if self.read_phase == ReadPhase.RESPONSE_HEADER:
                    # RESPONSE header tells that following data
                    # is a valid response message
                    _, response_body_len = self.read_block_header(
                        socket=rs, expected_key='RESPONSE')
                    self.read_phase = ReadPhase.STATUS_CODE
                elif self.read_phase == ReadPhase.STATUS_CODE:
                    # retreive search status code
                    status_code, size = self.read_block_value(
                        socket=rs, expected_key='STATUS-CODE', val_type='i')
                    success, msg = self.handle_status_code(status_code)
                    # if status code returned error, return the error message
                    # Do not further go on to SONG reading phase.
                    if not success:
                        print('Status code returned error message {}'.format(msg))
                        returned_songs = None
                        self.read_phase = ReadPhase.DONE
                        break
                    self.read_phase = ReadPhase.SONGHEADER
                    response_body_len -= size  # size of STATUS_CODE data
                elif self.read_phase == ReadPhase.SONGHEADER:
                    if response_body_len <= 0:
                        print('No more songs to find')
                        self.read_phase = ReadPhase.DONE
                        break

                    _, song_body_len = self.read_block_header(
                        socket=rs, expected_key='SONG')
                    response_body_len -= MESSAGE_HEADER_SIZE
                    assert response_body_len > 0  # should have some more data to read
                    self.read_phase = ReadPhase.SONGBODY
                elif self.read_phase == ReadPhase.SONGBODY:
                    songbody_value_length = 0
                    info = []
                    # iterate and try to find all possible key-value pairs from body
                    while song_body_len > songbody_value_length:
                        song_key, val_len = self.read_block_header(socket=rs)
                        if song_key == 'SONG-ID':
                            uid = self.read_int(sock=rs)
                            info.append(('uid', uid))
                        elif song_key == 'ARTIST':
                            artist = self.read_string(
                                rs, expected_len=val_len, strip_null_char=True)
                            #print(artist[0])
                            #print(artist[1])
                            info.append(('artist', artist[0]))
                        elif song_key == 'TITLE':
                            title = self.read_string(
                                rs, expected_len=val_len, strip_null_char=True)
                            info.append(('title', title[0]))
                        elif song_key == 'ALBUM':
                            album = self.read_string(
                                rs, expected_len=val_len, strip_null_char=True)
                            info.append(('album', album[0]))
                        elif song_key == 'BER':
                            ber = self.read_double(rs)
                            info.append(('ber', ber))
                        elif song_key == 'OFFSET-TIME':
                            offset_time = self.read_int(rs)
                            info.append(('offset-time', offset_time))
                        elif song_key == 'OFFSET':
                            offset = self.read_int(rs)
                            info.append(('offset', offset))
                        elif song_key == 'TOGGLE':
                            toggle = self.read_int(rs)
                            info.append(('toggle', toggle))
                        else:
                            raise ValueError(
                                'Received unknown key: {}'.format(song_key))

                        # mark the amount read
                        songbody_value_length += MESSAGE_HEADER_SIZE + val_len

                    # save the song information to return list
                    #returned_songs.append(dict(info))
                    returned_songs = dict(info)

                    # subtract the amount read
                    response_body_len -= song_body_len
                    if response_body_len == 0:
                        self.read_phase = ReadPhase.DONE
                    else:  # there can be more songs to read
                        self.read_phase = ReadPhase.SONGHEADER
                else:
                    in_socks.clear()
                    done = True
                    break
            # break the loop if done
            if done:
                break
        self.sock.close()  # close sockets when finished
        return status_code, returned_songs, msg


def recvall(sock, size):
    data = b''

    remain = size
    while remain > 0:
        packet = sock.recv(1024)
        if packet == None or len(packet) == 0:
            time.sleep(1)
        else:
            data += packet
            remain -= len(packet)

    return data


#############################################################################################################
def make_fprint(mp3, host):
    
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #print(host)
        sock.connect((host, 11000))

        total_sent = 0
        remain = len(mp3)
        while remain > 0:
            if remain >= 16 * 1024:
                packet_size = 16 * 1024
            else:
                packet_size = remain

            packet = mp3[total_sent:(total_sent + packet_size)]
            sock.sendall(struct.pack('!I' + str(packet_size) + 's',  packet_size, packet))

            total_sent += packet_size
            remain     -= packet_size
        sock.sendall(struct.pack('!I',0))

        fp_len, = struct.unpack('!I', sock.recv(4))
        if fp_len > 0:
            return recvall(sock, fp_len)
    except:
        traceback.print_exc()
        print('host: %s' % host)
        pass

    if sock != None:
        sock.close()

    return None



if __name__ == '__main__':
    
    #set audiofile and fingerprint file name by argument
    audiofile = "/home1/irteam/mygit/naversample/fp"+sys.argv[1]+".wav"
    fpfilename = "/home1/irteam/mygit/naversample/fpfile"+sys.argv[1]+".fp"
	
    f = open(audiofile, 'rb')
    audio = f.read()
    f.close()

	# if cannot search fingerprint file
    if(len(audio)==0):
        print("FPERROR")
        sys.exit(1)

    fprint = make_fprint(audio,"10.114.45.138" )
    f = open(fpfilename, 'wb')
    f.write(fprint)
    f.close()    
   
    f = open(fpfilename, 'rb')
    fp = f.read()
    f.close()

	#13300 / 10.112.110.119
    searcher = SmSearcher("10.112.110.119", 13300)

    status_code, returned_song, msg = searcher.search(fp[1024:2048])
    #print(returned_song['uid'])
    #print(returned_song['title'])
    #print(returned_song['ber'])
            
    
    if status_code == 200 :
        result=str(returned_song['uid'])+"|"+str(returned_song['artist'])+"|"+str(returned_song['title'])+"|"+str(returned_song['ber']);
	      
        print(result)
    else:
	    print("NULL")
     
        
    f.close()
