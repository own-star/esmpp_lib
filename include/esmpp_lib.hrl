-define(LOG_DEBUG(Format, Args),    lager:log(debug, self(), Format, Args)).
-define(LOG_INFO(Format, Args),     lager:log(info, self(), Format, Args)).
-define(LOG_WARNING(Format, Args),  lager:log(warning, self(), Format, Args)).
-define(LOG_ERROR(Format, Args),    lager:log(error, self(), Format, Args)).
-define(LOG_CRITICAL(Format, Args), lager:log(critical, self(), Format, Args)).

-define(BIND(Length, ComId, SeqNum, SysId, LenId, Pass, LenP, SysType, LenT,
                IntVer, AddrTon, AddrNpi, AddrRange, LenR), <<
Length:32/integer,                 %% command_length 
ComId:32/integer,                  %% command_id  
0:32/integer,                      %% command_status 
SeqNum:32/integer,                 %% sequence_number
SysId:LenId/binary, 0:8/integer,   %% sytem_id 
Pass:LenP/binary, 0:8/integer,     %% password 
SysType:LenT/binary, 0:8/integer,  %% system_type 
IntVer:8/integer,                  %% interface version (0x34 or 0x50)
AddrTon:8/integer,                 %% addr_ton if not known set 0    
AddrNpi:8/integer,                 %% addr_npi if not known set 0
AddrRange:LenR/integer %% 0:8/integer %% address_range if not known set 0 TODO !!!!!!!!
>>).

-define(UNBIND(SeqNum), <<
16:32/integer,                     %% command_length 
6:32/integer,                      %% command_id 
0:32/integer,                      %% command_status 
SeqNum:32/integer                  %% sequence_number
>>).

-define(UNBIND_RESP(SeqNum, Status), <<
16:32/integer,                     %% command_length 
2147483654:32/integer,             %% command_id 
Status:32/integer,                 %% command_status 
SeqNum:32/integer                  %% sequence_number
>>).

-define(GENERIC_NACK(SeqNum, Status), <<
16:32/integer,                     %% command_length 
2147483648:32/integer,             %% command_id 
Status:32/integer,                 %% command_status 
SeqNum:32/integer                  %% sequence_number
>>).


-define(DELIVER_SM(Length, SeqNum, ServType, LenT, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD, ESMClass, RDFlag, DataCoding, LenSms, Text), <<
%% Mandatory parameters
Length:32/integer,               %% command_length                  
5:32/integer,                    %% command_id 
0:32/integer,                    %% command_status NONE in native packet !!!!!
SeqNum:32/integer,               %% sequence_number
ServType:LenT/binary, 0:8/integer,%% service_type                    
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer,  %% dest_addr
ESMClass:8/integer,                     %% esm_class
0:8/integer,                     %% protocol_id
0:8/integer,                     %% priority_flag
0:8/integer,                     %% schedule_delivery_time NOW immediate_delivery TODO !!!
0:8/integer,                     %% validity_period NOW SMSC default              TODO !!!
RDFlag:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
0:8/integer,                     %% replace_if_present_flag NOW default don't replace
DataCoding:8/integer,            %% data_coding
0:8/integer,                     %% sm_default_msg_id NOW unused
LenSms:8/integer,                %% sm_length
Text:LenSms/binary               %% short_message 
>>).


-define(SUBMIT_SM(Length, SeqNum, ServType, LenT, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD, RDFlag, DataCoding, LenSms, Text), <<
%% Mandatory parameters
Length:32/integer,               %% command_length                  
4:32/integer,                    %% command_id 
0:32/integer,                    %% command_status NONE in native packet !!!!!
SeqNum:32/integer,               %% sequence_number
ServType:LenT/binary, 0:8/integer,%% service_type                    
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer,  %% dest_addr
0:8/integer,                     %% esm_class
0:8/integer,                     %% protocol_id
0:8/integer,                     %% priority_flag
0:8/integer,                     %% schedule_delivery_time NOW immediate_delivery TODO !!!
0:8/integer,                     %% validity_period NOW SMSC default              TODO !!!
RDFlag:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
0:8/integer,                     %% replace_if_present_flag NOW default don't replace
DataCoding:8/integer,            %% data_coding
0:8/integer,                     %% sm_default_msg_id NOW unused
LenSms:8/integer,                %% sm_length
Text:LenSms/binary               %% short_message 
>>).


-define(SUBMIT_SM_CUT(Length, SeqNum, ServType, LenT, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD, DataCoding, LenMsg, Chunk, LenChunk, SarRefNum, 
     SarSegNum, SarTotSeg), <<

%% Mandatory parameters
Length:32/integer,               %% command_length                  
4:32/integer,                    %% command_id 
0:32/integer,                    %% command_status NONE in native packet !!!!!
SeqNum:32/integer,               %% sequence_number
ServType:LenT/binary, 0:8/integer,%% service_type                    
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer,  %% dest_addr
64:8/integer,                    %% esm_class
0:8/integer,                     %% protocol_id
0:8/integer,                     %% priority_flag
0:8/integer,                     %% schedule_delivery_time NOW immediate_delivery TODO !!!
0:8/integer,                     %% validity_period NOW SMSC default              TODO !!!
1:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
0:8/integer,                     %% replace_if_present_flag NOW default don't replace
DataCoding:8/integer,            %% data_coding
0:8/integer,                     %% sm_default_msg_id NOW unused
LenMsg:8/integer,                %% sm_length
5:8/integer,                     %% UDH
0:8/integer,
3:8/integer,
SarRefNum:8/integer,   %% reference for a particular concatenated short message
SarTotSeg:8/integer,   %% total number of fragments
SarSegNum:8/integer,   %% sequence number of a particular message
%524:16/integer, 2:16/integer, SarRefNum:16/integer,        %%SAR    %% reference for a particular concatenated short message
%526:16/integer, 2:16/integer, SarTotSeg:16/integer,                 %% total number of fragments
%527:16/integer, 2:16/integer, SarSegNum:16/integer,                 %% sequence number of a particular message
Chunk:LenChunk/binary            %% short_message 
>>).

-define(SUBMIT_SM_MSG_PAYLOAD(Length, SeqNum, ServType, LenT, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD, DataCoding, LenSms, Text), <<
%% Mandatory parameters
Length:32/integer,               %% command_length                  
4:32/integer,                    %% command_id 
0:32/integer,                    %% command_status NONE in native packet !!!!!
SeqNum:32/integer,               %% sequence_number
ServType:LenT/binary, 0:8/integer,%% service_type                    
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer,  %% dest_addr
0:8/integer,                     %% esm_class
0:8/integer,                     %% protocol_id
0:8/integer,                     %% priority_flag
0:8/integer,                     %% schedule_delivery_time NOW immediate_delivery TODO !!!
0:8/integer,                     %% validity_period NOW SMSC default              TODO !!!
1:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
0:8/integer,                     %% replace_if_present_flag NOW default don't replace
DataCoding:8/integer,            %% data_coding
0:8/integer,                     %% sm_default_msg_id NOW unused
0:8/integer,                     %% sm_length
%0:1/binary,                      %% short_message 
1060:16/integer,                 %% message_payload
LenSms:16/integer,
Text:LenSms/binary
>>).


-define(DATA_SM(Length, SeqNum, ServType, LenT, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD, DataCoding, Payload, PayLen), <<
Length:32/integer,               %% command_length                  
259:32/integer,                  %% command_id 
0:32/integer,                    %% command_status 
SeqNum:32/integer,               %% sequence_number
ServType:LenT/binary, 0:8/integer,%% service_type                    
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer,  %% dest_addr
0:8/integer,                     %% esm_class
1:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
DataCoding:8/integer,            %% data_coding
7:16/integer,                    %% OPTION dest_bearer_type                            %% TODO Optional parameters
1:16/integer,
1:8/integer,
25:16/integer,                   %% payload_type    
1:16/integer,
0:8/integer,
1060:16/integer,                 %% message_payload
PayLen:16/integer,
Payload:PayLen/binary
>>).

-define(DATA_SM_RESP(Length, Satus, SeqNum, MsgId, LenId), <<
Length:32/integer,                 %% command_length 
2147483907:32/integer,             %% command_id 
Status:32/integer,                 %% command_status 
SeqNum:32/integer,                 %% sequence_number set as original enq_link  
MsgId:LenId/binary, 0:8/integer    %% message_id SMSC identifier 
%% TODO Optional parameters
>>).

-define(DELIVER_SM_RESP(Length, Status, SeqNum), <<
Length:32/integer,            %% command_length 
2147483653:32/integer,        %% command_id 
Status:32/integer,            %% command_status
SeqNum:32/integer,            %% sequence_number
0:8/integer                   %% msg_id SMSC identifier from DELIVER_SM options (unused) 

%% TODO Optional parameters (only for 5.0 version)
>>).

-define(QUERY_SM(Length, SeqNum, MsgId, LenId, SAddrTon, SAddrNpi, SAddr, LenS), <<
Length:32/integer,               %% command_length 
3:32/integer,                    %% command_id 
0:32/integer,                    %% command_status
SeqNum:32/integer,               %% sequence_number
MsgId:LenId/binary, 0:8/integer, %% msg_id SMSC identifier from submit_sm_resp
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAddr:LenS/binary, 0:8/integer   %% source_addr
>>).

-define(ENQUIRE_LINK(SeqNum), <<
16:32/integer,                     %% command_length 
21:32/integer,                     %% command_id 
0:32/integer,                      %% command_status 
SeqNum:32/integer                  %% sequence_number
>>).

-define(ENQUIRE_LINK_RESP(SeqNum), <<
16:32/integer,                     %% command_length 
2147483669:32/integer,             %% command_id 
0:32/integer,                      %% command_status 
SeqNum:32/integer                  %% sequence_number set as original enq_link  
>>).

-define(CANCEL_SM(Length, SeqNum, MsgId, LenId, SAddrTon, SAddrNpi, SAdress, LenS, 
     DAddrTon, DAddrNpi, DAddr, LenD), <<
Length:32/integer,               %% command_length 
8:32/integer,                    %% command_id 
0:32/integer,                    %% command_status 
SeqNum:32/integer,               %% sequence_number
0:8/integer,                     %% service_type                    
MsgId:LenId/binary, 0:8/integer, %% msg_id SMSC identifier from submit_sm_resp
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
DAddrTon:8/integer,              %% dest_addr_ton
DAddrNpi:8/integer,              %% dest_addr_npi
DAddr:LenD/binary, 0:8/integer   %% dest_addr
>>).

-define(REPLACE_SM(Length, SeqNum, MsgId, LenId, SAddrTon, 
                    SAddrNpi, SAdress, LenS, LenTxt, Txt), <<
Length:32/integer,               %% command_length 
7:32/integer,                    %% command_id 
0:32/integer,                    %% command_status 
SeqNum:32/integer,               %% sequence_number
MsgId:LenId/binary, 0:8/integer, %% msg_id SMSC identifier from submit_sm_resp
SAddrTon:8/integer,              %% source_addr_ton
SAddrNpi:8/integer,              %% source_addr_npi
SAdress:LenS/binary, 0:8/integer,%% source_addr
0:8/integer,                     %% schedule_delivery_time NOW immediate_delivery TODO !!!
0:8/integer,                     %% validity_period NOW SMSC default              TODO !!!
1:8/integer,                     %% registered_delivery NOW delivery receipt requested TODO !!!
0:8/integer,                     %% sm_default_msg_id NOW unused
LenTxt:8/integer,                %% sm_length
Txt:LenTxt/binary                %% short_message 

%% TODO options (only for version 5.0)
>>).
