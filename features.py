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
        #print(m.group(0))    
        #Check if the subroutines are nested
        if re.search('call\s+sub_', m.group(1)):
            nested_subroutine.append(m.group(0).split()[0])
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
                        str_remove=k.group(0);
                        if str_final=="":
                                str_final= m.group(0).replace(str_remove,'')
                        else:
                                str_final=str_final.replace(str_remove,'')
        else:
                str_final=m.group(0);
                
        #Remove the jumps inside the routines and extract the instruction codes
        found = re.search(r'loc_\w+:', str_final)
        if found:
                for k in re.finditer(r'(?=loc\w+:(.*?)(loc\w+:|sub_\w+\s+endp))',str_final,re.DOTALL):
                    rem= k.group(1)[0:len(k.group(1))-10];
                    if str=="":
                        str= str_final.replace(rem,' ')
                    else:
                        str=str.replace(rem,' ')

                
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
subroutine = ""
features = []
features_sub = ""
subroutine_name = ""
subroutine_string = ""
filelist = ""
filecontent = ""
file_list = ""
remove_str = ""
for n in re.finditer(r'.text:\w{8}\s+(;.*?)end\s',open('C:/Users/Deepthi Arthisha/Documents/0A32eTdBKayjCWhZqDOQ.asm','r', encoding="latin-1").read(),re.DOTALL):
        filecontent = n.group(0)
        for a in re.finditer(r'sub_\w+\s+proc(.*?)endp',filecontent,re.DOTALL):
                str_remove=a.group(0)
                if file_list=="":
                        file_list= n.group(0).replace(str_remove,'')
                else:
                        file_list=file_list.replace(str_remove,'')
        for m1 in re.finditer(r'(.text:)(\w{8})\s(\w{2}\s+)+call\s+(sub_\w+)',filecontent,re.DOTALL):
                subroutine_name = m1.group(4)
                subroutine = subroutine_list[subroutine_name];
                features = subroutine.split('|')
                for i in range(len(features)):
                        features_sub += ".text:11111111 " + features[i] + '\n'
                remove_str=m1.group(0)
                if file_list=="":
                        file_list= n.group(0).replace(remove_str,features_sub)
                else:
                        file_list=file_list.replace(remove_str,features_sub)            
        for n1 in re.finditer(r'(.text:)(\w{8})\s(\w{2})',file_list):
                if not (n1.group(3) == "00" or n1.group(3) == "CC" or n1.group(3) == "dd" or n1.group(3) == "db" or n1.group(3) == "dw" or n1.group(3) == "dq" or n1.group(3) == "dt"):
                        subroutine+=n1.group(3)+'|';
print(subroutine)       
write_asm = open('feature.txt',"w")   
write_asm.write(subroutine);
                                
k=input("press close to exit") 
        
        

            


