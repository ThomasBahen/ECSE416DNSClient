import socket 
import sys
import random
import numpy as np


class DNS_Client():
    def _init_(self):
       self.DNS_IP = '132.216.44.21'
       self.PORT = 53
       self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       
    def connect_DNS(self):
        """
        connects via socket to a DNS Server
        """
        self.s.connect((self.DNS_IP, self.PORT))
    
    def convert_16bit_array_to_8bit_array(self, array):
        """
        takes input 16 bit array, goes through each value and splits it into 2 8 bit entries
            that are then used to fille out a new corresponding 8 bit arra
        """
        new_array = np.zeros(2*len(array), dtype='uint8')
        i=0
        for item in array:
            part1 = item>>8
            part2=item&255
            new_array[i] = part1
            new_array[i+1] = part2
            i +=2;
        return new_array
    
    def build_query_header(self):
        """
        builds a standard header for query or answers.
            Input:
                no input required. This builds a standard DNS query header in the form of an array
            Output:
                np uint8 array representing the full header.
        returns it in the form of a uint8 np. array. TO this array, append the question and answer segments. 
        
        """
        header_id_part1 = [np.uint16(random.randint(0, 256))]
        packet_datagram = bytearray(header_id_part1)
        viewable_packet = np.array(packet_datagram)
        
        header_id_part2 = np.uint16(random.randint(0, 255))
        packet_datagram.append(header_id_part2)
        
        header_id = np.uint16(random.randint(0, 65535))
        print(packet_datagram)
        
        
        #Set first bit QR to 1, for query
        QR = np.uint16(0)
        
        #Set OPCODE to 0 representing standard query.
        OPCODE = np.uint16(0)
        
        #Set AA to 0 as this is not a response
        AA = np.uint16(0)
        
        #Set TC bit to 0 to indicate that this message was not truncated. 
        TC = np.uint16(0)
        
        #Set RD to one to signiify we desire a recursive query. 
        #This means the server will ask its friends recursively to see if they know the website
        RD = np.uint16(pow(2, 8))
        
        #setting the RA bit to 1. If, when we receive the packet back it is set to 0, recursive queries are supported.
        RA = np.uint16(0)
        
        #Setting z to zero for future use
        Z = np.uint16(0)
        
        # set the first two rows
        first_row = header_id;
        second_row = QR + OPCODE + AA + TC + RD + RA 
        third_row = np.uint16(1);
        fourth_row = np.uint16(0)
        fifth_row = np.uint16(0)
        sixth_row = np.uint16(0)
        
        header_list = ([first_row, second_row, third_row, fourth_row, fifth_row, sixth_row])
        header = np.array(header_list, dtype='uint16')
        new_header = self.convert_16bit_array_to_8bit_array(header)
        
        return new_header
       
    def build_question(self, dns_name):
       """
       Given a DNS name like www.mcgill.ca, and maybe some other features to be added slightly after, 
       returns a numpy uint8 array that represents the question packet of the datagram
       Input:
           dns_name: the string dns_name for the IP address/info you wish to find from the DN server
       Output:
           A uint8 array representing the question packet of the datagram
       """
       ## build_name first
       output_arr = np.array([], dtype='uint8')
       string_list = list(dns_name)
       counter = 0
       length_counter = 0
       for character in string_list:
           if(character != '.'):
               counter+=1
               length_counter+=1
               output_arr = np.append(output_arr, ord(character))
           if(character == '.'):
               
               output_arr = np.insert(output_arr, counter-length_counter, length_counter)
               counter+=1
               length_counter = 0
       output_arr = np.insert(output_arr, counter-length_counter, length_counter)
       output_arr = np.append(output_arr, 0)
        
        #set the QTYPE. Set to 0x0001 for now, but needs to be variable
       output_arr = np.append(output_arr, 0)     
       output_arr = np.append(output_arr, 1)    
        
        #set the QClass. Must always be 0x0001
       output_arr = np.append(output_arr, 0)
       output_arr = np.append(output_arr, 1)
        
       return output_arr
       
    def decode_question(self, question_array):
        """
        Given a unit8 array that contains all the bytes pertaining to the question (with possibly more appending to it), decode that value, return the name associated with the question
        and the final index of the question
        Input:
            question_array: the unit8 np array with the first index being the first octet of the question. Usually starts with name
        Output:
            Decoded name string as well as the final index associated with the question.
        """
        
        string_name, string_end_index = self.decode_name(question_array)
        
        qTYPE = np.uint16( (question_array[string_end_index+1]<<8) + question_array[string_end_index + 2])
        
        qCLASS = np.uint16((question_array[string_end_index+3]<<8) + question_array[string_end_index + 4])
        if (qCLASS != 1):
            print("Error: QCLASS bytes in question packet indicates this is not an internet communication")
            return
        return string_name, string_end_index + 4
            
            
        
        
    def decode_name(self, name_array):
        """
        Given an array that starts at the first entry of the name section, goes through the name, decodes it from ascii code to appropriate char, and returns the name and the final index at which the name ended (with 00) 
        Input:
            name_array: the np array with the first index being the first part of the name we wish to decode
        Output:
            Decoded name, and final index
        """
       
        current_value = name_array[0]; #update current value. When reach current_value = 00, then end. 
        string_arr = ''
        outer_counter=1
        while(current_value != 0):
            counter = 0
            next_step = current_value
            while(counter < next_step):
                letter = chr(name_array[outer_counter])
                string_arr += letter
                counter += 1
                outer_counter+=1
            string_arr+='.'
            current_value = name_array[outer_counter]
            outer_counter+=1
        string_arr = string_arr[:-1]
        return string_arr, outer_counter-1
            
        
        
    def decode_answer(self, answer):
        """
        Decodes answer given by DNS server. 
            Input: 
                numpy array of the answer string
            Output: 
                Either returns IP Address, or DNS alias
        """
        answer_output = ''
        
        header_id = np.uint16((answer[0]<<8) + answer[1])
        
        flags = np.uint16((answer[2]<<8) + answer[3])
      
        QR = answer[2]>>7
        
        truncated = answer[2]&1
        
        question_count = np.uint16((answer[4]<<8) + answer[5])
        
        answer_count = np.uint16((answer[6]<<6) + answer[7])
        
        #array describing the question string and up. It is up to decode to know when the question ends and anything else after that begins
        question_array = answer[12:]
        #decode question must both decode the string of words given by the dns server, but alsoreturn the last index of the question
        question, question_end_index = self.decode_question(question_array);
        
        answer_start_index = 12 + question_end_index + 1
        pointer_to_start_of_name = answer[answer_start_index + 1] #index at which the name of the string starts.
        answer_name = answer[pointer_to_start_of_name:]
        #decode_name must return the decoded name and the end index, like decode_question
        answer_name, answer_name_end_index = self.decode_name(answer_name)
        
        #must be either:
        #x0005 - CNAME
        #x000f - type MX query
        #x0002 - type NS query
        #x0001 type-A query
        response_type = np.uint16((answer[answer_start_index + 2]<<8) + answer[answer_start_index + 3])
        
        
        #check class is 0x0001
        if(np.uint16((answer[answer_start_index + 4]<<8 )+ answer[answer_start_index + 5] )!= 1):
            print("Error: DNS QCode  in answer packet specifies this packet does not have to do with internet addresses")
        
        time_out = np.uint32((answer[answer_start_index + 6]<<24) + (answer[answer_start_index + 7]<<16) + (answer[answer_start_index + 8]<<8) + answer[answer_start_index + 9])
        
        rDLENGTH = np.uint16((answer[answer_start_index + 10]<<8) + answer[answer_start_index+11])
        
        for i in range(rDLENGTH):
            answer_output += (str(answer[answer_start_index + 12 + i]) + '.')
        answer_output = answer_output[:-1]
     
            
        
        return answer_output
        
    def convert_nparray_bytesarray(array):
        """
        takes uint8 array. Loops through it, converting each entry to binary and appending it to a string
        """
        string_output = ''
        for item in array:
            binary = bin(item)
            string_output+=binary
        return string_output


#creates DNS_Client with predetermined  socket port and DNS server IP
dns_client = DNS_Client()
#connects to DNS server
DNS_IP = '74.116.184.28' #'132.216.44.21'
PORT = 53
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((DNS_IP, PORT))

header = dns_client.build_query_header()

name = "www.mcgill.com"
question = dns_client.build_question(name)
datagram = np.append(header, question)
datagram = datagram.astype('uint8')

datagram = datagram.tobytes()

#send datagram to DNS_server
s.sendall(datagram)
#get response
data = s.recv(1024)  
    

#load response into numpy array
response= np.frombuffer(data, dtype=np.uint8)

IP_address = dns_client.decode_answer(response)

print("IP address of requested website: " + IP_address)
    