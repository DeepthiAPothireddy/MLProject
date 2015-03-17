import re

p=""
final=""
str=""
str_final=""
instruction_set_1=[]
instruction_set_2=[]
no_nested_subroutine=[]
nested_subroutine=[]
address_instance=[]
destination_instance=[]
found1='true'
#filename = "C:\Users\Deepthi Arthisha\Dropbox\Subject\Pattern Recognition\malware classification\SML_Project\SML_Project";


#Find the subroutines in the asm code that starts with sub_<Proc_name> and ends with endp
for m in re.finditer(r'sub_\w+\s+proc(.*?)endp',open('C:/Users/Deepthi Arthisha/Documents/0A32eTdBKayjCWhZqDOQ.asm','r', encoding="latin-1").read(),re.DOTALL):
              
        #Check if the subroutines are nested
        if re.search('call\s+sub_', m.group(1)):
            nested_subroutine.append(m.group(0).split()[0])
            #print(m.group(1))
            flag=1;
            
            for m1 in re.finditer(r'(.text|.data):(\w{8})\s(\w{2}\s+)+call\s+(sub_\w+)',m.group(0)):
                   address_instance.append(m1.group(2))
                   destination_instance.append(m1.group(4))
            hash_call_address={k:v for k, v in zip(address_instance, destination_instance)} #Store the source and destination address for nested subroutines
            
            
        else:
            no_nested_subroutine.append(m.group(0).split()[0]);
            flag=0;

        #str_final=m.group(0);
        found=re.search(r'.text:\w{8}\s+(;.*?).text:\w{8}\s\w{2}',m.group(0))
        if found:
                for k in re.finditer(r'.text:\w{8}\s+(;.*?).text:\w{8}\s\w{2}',m.group(0),re.DOTALL):
                        #print k.group(0);
                        str_remove=k.group(0);
                        if str_final=="":
                                str_final= m.group(0).replace(str_remove,'')
                        else:
                                str_final=str_final.replace(str_remove,'')
        else:
                str_final=m.group(0);
        #print str_final;
                
        #Remove the jumps inside the routines and extract the instruction codes
        found = re.search(r'loc_\w+:', str_final)
        if found:
                for k in re.finditer(r'(?=loc\w+:(.*?)(loc\w+:|sub_\w+\s+endp))',str_final,re.DOTALL):
                    rem= k.group(1)[0:len(k.group(1))-10];
                    if str=="":
                        str= str_final.replace(rem,' ')
                    else:
                        str=str.replace(rem,' ')

                #print str;
                
                for m1 in re.finditer(r'.text:(\w{8})\s(\w{2})',str):
                    if flag==1:
                            if m1.group(1) in hash_call_address:
                                    final+=hash_call_address[m1.group(1)]+'|';
                            else:      
                                    final+=m1.group(2)+'|';

                    else:
                            final+=m1.group(2)+'|';
                            
                           
                if flag==1:
                    instruction_set_1.append(final);
                else:
                    instruction_set_2.append(final);

                final="";
                str="";

        #No jumps in subroutines encountered
        else:
                for m1 in re.finditer(r'(.text|.data):(\w{8})\s(\w{2})',str_final):

                        if flag==1:
                            if m1.group(2) in hash_call_address:
                                    final+=hash_call_address[m1.group(2)]+'|';
                            else:      
                                    final+=m1.group(3)+'|';

                        else:
                            final+=m1.group(3)+'|';
                         
                if flag==1:
                    instruction_set_1.append(final);
                else:
                    instruction_set_2.append(final);
                final="";

#Hash Map creation that stores subroutine names as keys and sequence of instructions delimited by '|' as values              
hash_nested={k:v for k, v in zip(nested_subroutine, instruction_set_1)}
hash = {k:v for k, v in zip(no_nested_subroutine, instruction_set_2)}

#Recursively replace the nested subroutines with the required sequence of instructions from hash or hash_nested
for key in hash_nested:
        found=re.search(r'((.*)(sub_\w{3,})+(.+))', hash_nested[key]);
        
        if(found):
                while(found1):                
                        for m1 in re.finditer(r'(.*)(sub_\w{3,})(.+)', hash_nested[key]):
                                                                       
                                if m1.group(2) in hash:
                                        x=hash_nested[key].replace(m1.group(2)+'|',hash[m1.group(2)])
                                        hash_nested[key]=x;
                                        
                                        
                                        
                                elif m1.group(2) in hash_nested:
                                        x=hash_nested[key].replace(m1.group(2)+'|',hash_nested[m1.group(2)])
                                        hash_nested[key]=x;
                                        
                                else:
                                        continue;
                        found1=re.search(r'((.*)(sub_\w{3,})+(.+))', hash_nested[key])  ;
        found1='true';          

#A subroutine hash map that has the final instruction sets for all subroutines.
subroutine_list = hash_nested.copy()
subroutine_list.update(hash)

#print(subroutine_list);

# Variable initialization
all_subroutine = ""
line_subroutine = ""
subroutine = ""
subroutine_name = ""
features = []
features_sub = []
subroutine_features = []
subroutine_string = ""
remove = []
a = ""
w= ""
        

#for m in re.finditer(r'.text\w+\s+(.?*)\n',open('C:/Users/Deepthi Arthisha/Documents/0A32eTdBKayjCWhZqDOQ.asm','r', encoding="latin-1").read(),re.DOTALL):
with open('C:/Users/Deepthi Arthisha/Documents/0A32eTdBKayjCWhZqDOQ.asm',"rU",encoding="latin-1") as asm:
        asmfile = asm.readlines()
        #asmstr = ' '.join(asmfile)
        for line in asmfile:
        #Getting subroutine values
                if re.search('call\s+sub_',line):
                        subroutine_name = re.findall(r'\bsub_\w+',line)
                        subroutine_string = ''.join(subroutine_name)
                                #subroutine_number = subroutine_string.replace("sub_",'')
                        subroutine_features = subroutine_list[subroutine_string]
                        features_sub = subroutine_features.split("|")
                        features.append(features_sub)
                elif re.search(r'\bsub_\w+',line):
                        if not ("call" in line or "endp" in line):
                                subroutine_name = re.findall(r'\bsub_\w+',line)
                                subroutine_string = ''.join(subroutine_name)
                                subroutine_string += "\s+endp"
                                i = asmfile.index(line)
                                #print(i)
                                for line in asmfile:
                                        if(re.search(subroutine_string,line)):                                 
                                                j = asmfile.index(line)
                                                #print(j)
                                asmfile[i:j] = ''                                       
                elif not ("db" in line or "dd" in line or "dw" in line or "dq" in line or "dt" in line or "cc" in line):
                        line = line.replace('\t',' ')
                        #print(line)
                        a = line.split(' ')
                        #a.replace('\t',' ')
                        #print(a)
                        if(re.search(r'.text:\w+',line)):
                                index = re.search(r'.text:\w+',line).start()
                                #print(index)
                        if(re.search(r'.data:\w+',line)):
                                index = re.search(r'.data:\w+',line).start()
                                #print(index)
                        if(re.search(r'.idata:\w+',line)):
                                index = re.search(r'.idata:\w+',line).start()
                                #print(index)
                        if (len(a) > index+1 and index == 0):
                                if not (a[index+1] ==''):
                                        features.append(a[index+1])
                        

print(features);

                

                            
                            
                    
            


