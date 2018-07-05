import socket
import struct
import select
import enum
import sys
import os
from xml.etree import ElementTree as ET
import com.whiwon.web.HomeController
'''
REQUEST Protocol

| Key            | Type   | Data                                                  |
|----------------|--------|-------------------------------------------------------|
| MSEARCH_VER    | String | "1.0"                                                 |
| DEVICE_INFO    | String | Device name and OS version                            |
| SAMPLE_RATE    | Int    | Sample rate. ex) 44100, 48000, 8000                   |
| BIT_PER_CH     | Binary | Sample bits. ex) 8, 16. Number of channel is 1 (mono) |
| ALBUM_IMG_SIZE | String | Format in "[width]x[height]". ex) "170x170" (default) |
| PCM            | Binary | PCM data                                              |
| NO_MORE_PCM    |        |                                                       |


RESPONSE Protocol

| Key            | Type   | Data                                                  |
|----------------|--------|-------------------------------------------------------|
| RSP_CODE       | Int    | 200 (占쎄쉐�⑨옙), 404 (筌륁궡媛쇽옙�벉), 408 (野껓옙占쎄퉳占쎈퓦筌욑옙 占쏙옙占쎌뿫占쎈툡占쎌뜍),    |
|                |        | 500 (占쎄땀�겫占� 占쎈퓠占쎌쑎), 900 (占쎄퐣甕곤옙 占쎌젟占쎌벥 占쎈퓠占쎌쑎 筌롫뗄苑�筌욑옙)          |
| RSP_DATA       | String | RSP_CODE揶쏉옙 200占쎌뵬 野껋럩�뒭                                 |
|                |        | 野껓옙占쎄퉳野껉퀗�궢�몴占� XML 占쎌굨占쎈뻼占쎌몵嚥∽옙 占쎌젫�⑨옙 (RSP_DATA)               |
| RSP_MSG        | String | RSP_CODE揶쏉옙 900占쎌뵬 野껋럩�뒭 占쎄퐣甕곌쑴肉됵옙苑� 占쎈퓠占쎌쑎筌롫뗄苑�筌욑옙�몴占� 癰귣�源�      |


The protocol requires that every message sent should be preceded by a 4-byte length
information. The server reads first the amount of length to read and then reads
the actual data that has the size provided.

For example, if we were to send message 'MSEARCH_VER', followed by '1.0',
then the message should contain: (11, 'MSEARCH_VAR', 3, '1.0')
'''


@enum.unique
class ReadPhase(enum.Enum):
    READ_KEY = 1
    READ_RSP_CODE = 2
    READ_RSP_DATA = 3
    READ_RSP_CONTINUE_READ_DATA = 4
    READ_RSP_MSG = 5
    READ_DONE = 6


@enum.unique
class WritePhase(enum.Enum):
    WRITE_PCM = 1
    WRITE_DONE = 2


class SongSearcher:
    def __init__(self, search_server_host, search_server_port):
        # create a socket and open connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((search_server_host, search_server_port))
        sock.setblocking(0)  # set to non-blocking mode
        self.sock = sock
        self.write_phase = ('write_pcm', 'done')

    def make_headers(self, sample_rate: int):
        """
        Create headers for the search.

        :param sample_rate: PCM sample rate. ex) 44100, 11025, 16000, etc.
        :return: network byte-encoded header message
        """
        # set up the search
        header_message = b''
        header_message += self.make_message_keyval('MSEARCH_VER', '1.0')
        header_message += self.make_message_keyval('DEVICE_INFO', 'TEST_FROM_AUDIO_PLATFORM')
        header_message += self.make_message_keyval('SAMPLE_RATE', str(sample_rate))
        header_message += self.make_message_keyval('BIT_PER_CH', '16')
        return header_message

    def make_message_keyval(self, key: str, value):
        """
        Encode key-value pairs into bytes.
        See protocol specification.

        :param key: key in string representation
        :param value: value in string or bytes representation
        :return: byte-encoded key-value pair message
        """
        # convert to bytes
        key_size = len(key)
        value_size = len(value)

        # encode value into bytes
        if type(value) == str:
            value = bytes(value, 'ascii')
        # '!' = pack in network byte-order
        # 'i10s' = 4-byte integer + length 10 byte string
        return struct.pack('!i{}si{}s'.format(key_size, value_size),
                           key_size,
                           bytes(key, 'ascii'),
                           value_size,
                           value)

    def __unpack_string(self, data: bytes, encoding: str):
        return struct.unpack('!{}s'.format(len(data)), data)[0].decode(encoding)

    def __unpack_int(self, data: bytes):
        return struct.unpack('!i', data)[0]

    def read_int(self, sock):
        """
        Read in 4-byte integer from socket.
        :param sock: socket to read from
        :return: integer value
        """
        data = sock.recv(4)
        if not data:
            return None
        return self.__unpack_int(data)

    def read_string(self, sock, expected_len: int, encoding: str='utf-8'):
        """
        Read in string data from socket.

        :param sock: socket to read from
        :param expected_len: expected length to be read.
                             actual data read might be less than this value.
        :param encoding: encoding to encode the bytes into string
        :return: (rsp_data, len_data)
           rsp_data: string value
           len_data: actual size read
        """
        data = sock.recv(expected_len)
        rsp_data = self.__unpack_string(data, encoding)
        return rsp_data, len(data)

    def read_bytes(self, sock, expected_len: int):
        """
        Read in bytes from socket.
        :param sock: socket to read from
        :param expected_len: expected length to be read
        :return: (rsp_data, len_data)
            rsp_data: bytes data
            len_data: actual bytes read
        """
        data = sock.recv(expected_len)
        return data, len(data)

    def search(self, in_file, sample_rate: int, send_bytes: int=1024):
        """
        Do the music search by reading PCM data from in_file. The PCM data should
        have equal sample_rate provided.
        
        :param in_file: PCM data file
        :param sample_rate: sample rate of audio source file
        :param send_bytes: amount of PCM bytes to send in a single packet
            <WARNING>: if this value is too large,
                       the data sent will be truncated and will misbehave
        :return: search_result that contains 'rsp_code', 'xml_data', 'error_message'
        """
        # list of sockets to read from, write to, and exceptionally read from
        inputs, outputs, xlists = [self.sock], [self.sock], []
        print(in_file)
        print(sample_rate)
        # search result to return
        search_result = {
            'rsp_code': -1,
            'xml_data': b'',
            'error_message': '',
        }

        # initial write and read phase
        write_phase = WritePhase.WRITE_PCM
        read_phase = ReadPhase.READ_KEY

        data_val_len = None  # size of search result data (xml) to be read further

        # begin bi-directional transmission
        # send header message
        header_message = self.make_headers(sample_rate)
        self.sock.send(header_message)

        # loop until all data sent or desired data received

        while True:
            # select operational sockets, and set timeout to 10
            readable, writable, _ = select.select(inputs, outputs, xlists, 10)

            ### WRITE stage
            
            for s in writable:
                if write_phase == WritePhase.WRITE_PCM:
                    pcm_data = in_file.read(send_bytes)
                    
                    if pcm_data:
                        sent = s.send(self.make_message_keyval('PCM', pcm_data))
                        # to simplify the code -- this is just a test script
                        # assert that all data are actually sent (including the 'headers')
                        assert(sent == (len(pcm_data) + 11))
                    else:
                        print('No more PCM data')
                        self.sock.send(
                            self.make_message_keyval('NO_MORE_PCM', value=''))
                        outputs.clear()  # remove writable socket
                        write_phase = WritePhase.WRITE_DONE  # indicate finished

            ### READ stage
            
            for s in readable:

                if read_phase == ReadPhase.READ_KEY:
                    print("read key")
                    # read in the key
                    recv_key_len = self.read_int(sock=s)
                    if recv_key_len is None:  # nothing to read yet...
                        break

                    recv_key, _ = self.read_string(sock=s,
                                                   expected_len=recv_key_len,
                                                   encoding='ascii')

                    # determine the next read phase state
                    if recv_key == 'RSP_CODE':
                        read_phase = ReadPhase.READ_RSP_CODE
                    elif recv_key == 'RSP_DATA':
                        read_phase = ReadPhase.READ_RSP_DATA
                    elif recv_key == 'RSP_MSG':
                        read_phase = ReadPhase.READ_RSP_MSG
                    else:
                        raise ValueError('Unknown value received: {}'.format(recv_key))
                elif read_phase == ReadPhase.READ_RSP_CODE:
                    print("read rsp code")
                    # read response code
                    _ = self.read_int(sock=s)
                    rsp_code = self.read_int(sock=s)
                    search_result['rsp_code'] = rsp_code  # save to search result

                    # do something according to the response code
                    if rsp_code == 200:
                        read_phase = ReadPhase.READ_KEY
                    elif rsp_code == 900:
                        read_phase = ReadPhase.READ_RSP_MSG  # server-defined error
                    else:
                        print("error!")
                        # failed - either because none was found or server error
                        read_phase = ReadPhase.READ_DONE
                        break
                elif read_phase in (ReadPhase.READ_RSP_DATA, ReadPhase.READ_RSP_CONTINUE_READ_DATA):
                    print("read data and read more data")
                    # read in response data
                    if read_phase == ReadPhase.READ_RSP_CONTINUE_READ_DATA:
                        print("read continue")
                        # no need to read the value length if it's continued
                        val_len = data_val_len
                    else:
                        val_len = self.read_int(sock=s)
                   

                    # leave this as bytes since it might contain incomplete data
                    rsp_data, read_len = self.read_bytes(sock=s, expected_len=val_len)
                    search_result['xml_data'] += rsp_data  # save to search result

                    # compare the amount read vs actual read
                    # rsp_data can be large due to lyrics, so it might not arrive with a single packet
                    print("read len:",read_len,"/ val len:",val_len)
               
                    #val -> �씫�뼱�빞 �븷 �뜲�씠�꽣 / read-> �씪�� �뜲�씠�꽣 /-> �씫�뼱�빞�븷 �뜲�씠�꽣媛� �궓�븘 �엳�쑝硫�
                    if data_val_len is None and read_len < val_len:
                        print("need to read more")
                        data_val_len = val_len - read_len
                        # tell it to continue reading data
                        read_phase = ReadPhase.READ_RSP_CONTINUE_READ_DATA
                        
                    elif read_len == val_len:
                        print("read all data")
                        data_val_len=0
                        
                    else:
                        print("datavallen: ",data_val_len ,"readlen: ",read_len)
            
                        
                        data_val_len -= read_len  # decrease the amount read
                            
                    if data_val_len == 0:
                        read_phase = ReadPhase.READ_DONE  # indicate done
                        inputs.clear()  # remove sockets from input socket list
                elif read_phase == ReadPhase.READ_RSP_MSG:
                    print("error")
                    # read response error message
                    val_len = self.read_int(sock=s)
                    rsp_msg, _ = self.read_string(sock=s,
                                                  expected_len=val_len,
                                                  encoding='utf-8')
                    search_result['error_message'] = rsp_msg
                    read_phase = ReadPhase.READ_DONE  # indicate done
                    inputs.clear()
                    print(rsp_msg)

            # finish
            if read_phase == ReadPhase.READ_DONE:
                print("done")
                break

        self.sock.close()

        # convert bytes to string
        search_result['xml_data'] = search_result['xml_data'].decode('utf-8')
        return search_result


if __name__ == '__main__':
    #if len(sys.argv) == 1:
    #    print('ERR: Provide the PCM file path to be used for search.')
     #   sys.exit(1)

    # host mrecog.search.naver.com == 125.209.210.38
    print("???")
    
    port = 10500
    host = 'msproxy.audiop.naver.com'
    host_ip = '125.209.210.38'
    dev_host = 'e0602.nhncorp.com'  # seems to be dead

    # get PCM file information
    #fname = sys.argv[1]  # has format 5_44100.pcm
    #fname = "3_16000.pcm"
    
    
    pcmfile = com.whiwon.web.HomeController.path+"/file.pcm"
    #pcmfile = "D:/project/mediademo/src/main/resources/ffmpeg-4.0-win64-static/bin/file.pcm"

    print(pcmfile)

    sample_rate = 44100

    # open the file and do the search
    search_sender = SongSearcher(host, port)
    with open(pcmfile, 'rb') as in_pcm_file:
        res = search_sender.search(in_pcm_file, sample_rate)

    # pretty print the result
    print('Response code: {}'.format(res['rsp_code']))
    print('Response data:\n{}\n'.format(res['xml_data']))
    print('Response msg: {}'.format(res['error_message']))
    result = format(res['xml_data'])
 
    #print("open")
    #f = open("D:/project/python_temp/audio.txt",'w')
    #print("write")
    #f.write(result)
    #print("close")
    #f.close();
    
    savexmlpath = com.whiwon.web.HomeController.path+"/audioresult.xml"
    #tree = ET.XML(result)
    #with open("D:/project/mediademo/src/main/resources/audioresult.xml", "w") as f:
      #  f.write(ET.tostring(tree).decode("utf-8"))
        
    
    tree = ET.XML(result)
    with open(savexmlpath, "w") as f:
        f.write(ET.tostring(tree).decode("utf-8"))
    f.close()
    
    

    print("end write")
    
    #print(result)
    
