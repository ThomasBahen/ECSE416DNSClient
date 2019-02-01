import socket 
import sys
import random
import argparse
import numpy as np
import select
import time


class DNS_Client():
    def _init_(self):
   
       self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       
    def connect_DNS(self):
        """
        connects via socket to a DNS Server
        """
        self.s.connect((args.server, args.p))
    
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
     #   print(packet_datagram)
        
        
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
       
    def build_question(self, dns_name, query_type):
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
       
       output_arr = np.append(output_arr, query_type) 
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
            
            
        
        
    def decode_name(self, name_array, **kwargs):
        """
        Given an array that starts at the first entry of the name section, goes through the name, decodes it from ascii code to appropriate char, and returns the name and the final index at which the name ended (with 00) 
        Input:
            name_array: the np array with the first index being the first part of the name we wish to decode
        Output:
            Decoded name, and final index
        """
        response_type = 0
        if 'response_type' in kwargs:
            response_type = kwargs['response_type']
        current_value = name_array[0]; #update current value. When reach current_value = 00, then end. 
        string_arr = ''
        outer_counter=1
        while(current_value != 0 and current_value != 192):
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
        if(response_type ==5):
            if current_value==0:
               output=outer_counter-2
            else:
               output=outer_counter-1
        else:
            output=outer_counter-1
        return string_arr, output
            
        
        
    def decode_answer(self, answer, header):
        """
        Decodes answer given by DNS server. 
            Input: 
                numpy array of the answer string
            Output: 
                Either returns IP Address, or DNS alias
        """
        answer_output = ''
        
        header_id = np.uint16((answer[0]<<8) + answer[1])
        
        header_check = np.uint16((header[0]<<8) + header[1])
        if (header_id != header_check):
            print("WRONG PACKET ERROR: response ID does not match query ID")
            return 10, 10, 0, 0, 0, 0
        
        flags = np.uint16((answer[2]<<8) + answer[3])
      
        qR = np.uint8(answer[2]>>7)
        
        opCode = np.uint8((answer[2]>>3)&15)
        
        truncated = np.uint8(answer[2]&1)
        
        isAuthority = np.uint((answer[2]<<2)&1)
       # if(isAuthority ==1):
          #  print("This server is an authoritative server\n")
            
        
        rCode = np.uint8(answer[3]&15)
        if(rCode == 0):
            pass# print("no error occurred")
        elif(rCode == 1):
            sys.exit("Format Error: The name server was unable to interpret the query due to it's format")
            return 10, 10, 0, 0, 0, 0
        elif(rCode == 2):
            sys.exit("Server Error: The DNS was unable to process the query due to an error on the server's side")
            return 10, 10, 0, 0, 0, 0
        elif(rCode == 3):
            sys.exit("NOTFOUND: Domain name referenced in query does not exist")
            return 10, 10, 0, 0, 0, 0
        elif(rCode == 4):
            sys.exit("Not Implemented Error: The DNS does not support the requested type of query")  
            return 10, 10, 0, 0, 0, 0
        elif(rCode == 5):
            sys.exit("RESTRICTION ERROR: The DNS refuses to perform the requested operation for policy reasons")
            return 10, 10, 0, 0, 0, 0
            
            
        
        
        question_count = np.uint16((answer[4]<<8) + answer[5])
        
        answer_count = np.uint16((answer[6]<<8) + answer[7])
        
        #array describing the question string and up. It is up to decode to know when the question ends and anything else after that begins
      #  question_array = answer[12:]
        #decode question must both decode the string of words given by the dns server, but alsoreturn the last index of the question
        #question, question_end_index = self.decode_question(question_array);
        
        #answer_start_index = 12 + question_end_index + 1
        #pointer_to_start_of_name = answer[answer_start_index + 1] #index at which the name of the string starts.
        #answer_name = answer[pointer_to_start_of_name:]
        #decode_name must return the decoded name and the end index, like decode_question
        answer_name = answer[12:]
        answer_name, answer_start_index = self.decode_name(answer_name)
        
        answer_start_index = 12+answer_start_index+1
        header_question = answer[:answer_start_index+4]
        #must be either:
        #x0005 - CNAME
        #x000f - type MX query
        #x0002 - type NS query
        #x0001 type-A query
        
        question_type = np.uint16((answer[answer_start_index ]<<8) + answer[answer_start_index + 1])
        
    
        
      
        
        offset = np.uint8(answer[answer_start_index+5])
        
        response_type = np.uint16((answer[answer_start_index + 6]<<8) + answer[answer_start_index + 7])
        
         #check class is 0x0001
        if(np.uint16((answer[answer_start_index + 8]<<8 )+ answer[answer_start_index + 9] )!= 1):
            print("Error: DNS QCode  in answer packet specifies this packet does not have to do with internet addresses")
            
        can_cache = np.uint32((answer[answer_start_index + 10]<<24) + (answer[answer_start_index + 11]<<16) + (answer[answer_start_index + 12]<<8) + answer[answer_start_index + 13])
       
        rDLENGTH = np.uint16((answer[answer_start_index + 14]<<8) + answer[answer_start_index+15])
        
        preference = 0
        final_index = 0
        if (response_type ==1):
            for i in range(rDLENGTH):
                answer_output += (str(answer[answer_start_index + 16 + i]) + '.')
            answer_output = answer_output[:-1]
            final_index = answer_start_index + 16 + i + 1
        elif (response_type == 15):
            preference = np.uint16((answer[answer_start_index + 16]<<8) + answer[answer_start_index+17])
            answer_output, end_index = self.decode_name(answer[answer_start_index +18:])
            final_index = answer_start_index + 18 + end_index +1
        elif (response_type ==2):
            answer_output, end_index = self.decode_name(answer[answer_start_index +16:])
            final_index =  answer_start_index+16 + end_index + 2
           # if(response_type ==5):
               # print("this is the name of an alias to :   " + answer_output )
        elif( response_type==5):
            answer_output, end_index = self.decode_name(answer[answer_start_index +16:], response_type=response_type)
            final_index =  answer_start_index+16 + end_index + 2
            
            
        
        return answer_output, response_type, can_cache, answer_count, isAuthority, preference, header_question, final_index 
        
    def convert_nparray_bytesarray(array):
        """
        takes uint8 array. Loops through it, converting each entry to binary and appending it to a string
        """
        string_output = ''
        for item in array:
            binary = bin(item)
            string_output+=binary
        return string_output

def remove_www(name):
    if (name[:4] == 'www.'):
        name = name[4:]
        
    return name

#create parser to fill arguments
parser = argparse.ArgumentParser()

parser.add_argument("-t", type=float, default = .5)
parser.add_argument("-r", type=int, default = 3)
parser.add_argument("-p", default = 53)
parser.add_argument("-mx",  action='store_const', dest='type', default=0x01, const=0x0F)
parser.add_argument("-ns",  action='store_const', dest='type', default=0x01, const=0x02)
parser.add_argument("server")
parser.add_argument("domainname")
args= parser.parse_args()


#creates DNS_Client with predetermined  socket port and DNS server IP
dns_client = DNS_Client()
#connects to DNS server


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setblocking(0)
s.settimeout(args.t)
 
s.connect((args.server, args.p))

print('DnsClient sending request for: '+ args.domainname)
print('Server: '+ args.server)
if(args.type==1):
    print('Request Type: A')
elif(args.type==2):
     print('Request Type: NS')
elif(args.type==15):
     print('Request Type: MX')
#get response
start = time.time()
for tries in range(args.r):
    header = dns_client.build_query_header()
    question = dns_client.build_question(args.domainname, args.type)
    datagram = np.append(header, question)
    datagram = datagram.astype('uint8')
    
    datagram = datagram.tostring()
    
    #send datagram to DNS_server
    s.sendall(datagram)
    timed_out = False
    ready = select.select([s], [], [], args.t)
    response_type = 10
    IP_address = 0
    if ready[0]:
        end = time.time()
        totalTime = (end-start)
        print('Response received after '+'%.4f' % totalTime+' seconds '+str(tries)+' retries')
        data = s.recv(4096)
         #load response into numpy array
        response= np.frombuffer(data, dtype=np.uint8)
        
       # name, response_type, can_cache, answer_count, authority, preference, header_question, final_index = dns_client.decode_answer(response, header)
        output = dns_client.decode_answer(response, header)
        name = output[0]
        response_type = output[1]
        can_cache = output[2]
        answer_count = output[3]
        authority = output[4]
        preference = output[5]
        header_question =output[6]
        final_index = output[7]
        decoded_values = [name, response_type, can_cache, answer_count, authority, preference]
        outputs = np.asarray(decoded_values)
        outputs = np.reshape(outputs, [1, len(outputs)])
        
        #outputs = 
        new_response = response
        while answer_count > 1:
            start = header_question# header_question
            rest = new_response[final_index:] # the rest of the response, not including what we just decoded 
            new_response = np.append(start, rest)
            new_output = dns_client.decode_answer(new_response, header)
            new_outputs = np.asarray(new_output[:-2])
            header_question = new_output[-2]
            final_index = new_output[-1]
            new_outputs = np.reshape(new_outputs, [1, len(new_outputs)])
            outputs = np.append(outputs, new_outputs, axis=0)
            answer_count-=1
            
    else:
        timed_out
        print("Packet timed out... trying again ")

    
   
    
    if (response_type != 10 and not timed_out): #response type 10 indicates if an error has occured
        print("Answer Section (" + str(len(outputs)) + " records)")
        i = 0
       
    
        for item in outputs:
            name = item[0]
            can_cache=item[2]
            authority=item[4]
            preference=item[5]
            response_type=int(item[1])
            if response_type != 5:
               if(response_type ==1):
                   print("IP\t" + str(name) + "\t " + str(can_cache) + "\t" + str(authority))
               elif(response_type ==2):
                    print("NS\t" + str(name) + "\t " + str(can_cache) + "\t" +  str(authority))
               elif(response_type ==15):
                    print("MX\t" + str(name) + "\t " + str(preference) + "\t " + str(can_cache)+ "\t" +  str(authority))
            else:
                 print("CNAME\t" + str(name) + "\t " + str(can_cache) + "\t" +  str(authority))
            answer_count-=1
        break
    elif (tries >= args.r):
       print("ERROR: exceeded the number of tries. Maybe another time")
       break
        
    




        
    
