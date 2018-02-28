-module(esmpp_lib_encoder).
-author('Alexander Zhuk <aleksandr.zhuk@privatbank.ua>').

-include("esmpp_lib.hrl").
-export([encode/2, encode/3]).

%% API
-spec encode(atom(), tuple()) -> 
    binary().
encode(Name, Param) ->
    encode(Name, Param, []).

-spec encode(atom(), list(), list()) -> 
    binary().
encode(Name, Param, List) ->
    case Name of
        transceiver ->
            bind(9, Param);
        transmitter ->
            bind(2, Param);
        receiver ->
            bind(1, Param);
        unbind ->
            unbind(Param);
        unbind_resp ->
            unbind_resp(List);
        generic_nack ->
            generic_nack(List);
        deliver_sm ->
            deliver_sm(List, Param);
        submit_sm ->
            submit_sm(List, Param);
        data_sm ->
            data_sm(List, Param);
        data_sm_resp ->
            data_sm_resp(List);
        deliver_sm_resp ->
            deliver_sm_resp(List);
        query_sm ->
            query_sm(List, Param);
        enquire_link ->
            enquire_link(Param);
        enquire_link_resp ->
            enquire_link_resp(List);
        cancel_sm ->
            cancel_sm(List, Param);
        replace_sm ->
            replace_sm(List, Param)
    end.

%% INTERNAL

bind(ComId, Param) ->
    SeqNum = proplists:get_value(seq_n, Param),
    SysId = get_binary(system_id, Param),
    LenId = byte_size(SysId),
    SysType = get_binary(system_type, Param),
    LenT = byte_size(SysType),
    Pass = get_binary(password, Param),
    LenP = byte_size(Pass),
    IVer = get_binary(interface_version, Param),
    IfaceVer = convert_smpp_version(IVer),  
    AddrTon = proplists:get_value(addr_ton, Param),
    AddrNpi = proplists:get_value(addr_npi, Param),
    Bin = ?BIND(1234, ComId, SeqNum, SysId, LenId, Pass, LenP, SysType, LenT,
                            IfaceVer, AddrTon, AddrNpi, 0, 8),
    Length = byte_size(Bin),
    ?BIND(Length, ComId, SeqNum, SysId, LenId, Pass, LenP, SysType, LenT, IfaceVer, 
                    AddrTon, AddrNpi, 0, 8).

unbind(Param) ->
    SeqNum = proplists:get_value(seq_n, Param),
    ?UNBIND(SeqNum).

unbind_resp([{sequence_number, SeqNum}]) ->
    ?UNBIND_RESP(SeqNum, 0).   

%% TODO 
generic_nack(List) ->
    SeqNum = proplists:get_value(sequence_number, List),
    ErrCode = proplists:get_value(status, List),
    ?GENERIC_NACK(SeqNum, ErrCode).
deliver_sm(List, Param) ->
    Handler = proplists:get_value(handler, Param), 
    Txt = get_binary(text, List),
    SeqNum = proplists:get_value(seq_n, Param),
    Daddr = get_binary(dest_addr, List),
    Saddr = get_binary(source_addr, List),
    ESMClass = get_binary(esm_class, List),
	RDFlag = get_binary(registered_delivery, List),
    {Encode, MaxLen} = exam_unicode(Txt, Param),
    Text = get_text_by_code(Encode, Txt),
    LenTxt = byte_size(Text),
    case LenTxt > MaxLen of
        false ->
            ServType = <<>>, %get_binary(service_type, Param),
%            ServType = get_binary(service_type, Param),
            LenType = byte_size(ServType),
            LenDaddr = byte_size(Daddr),
            LenSaddr = byte_size(Saddr),
            SaddrTon = proplists:get_value(source_addr_ton, Param),
            SaddrNpi = proplists:get_value(source_addr_npi, Param),
            DaddrTon = proplists:get_value(dest_addr_ton, Param),
            DaddrNpi = proplists:get_value(dest_addr_npi, Param),
            ok = Handler:sequence_number_handler([{sequence_number, SeqNum}|List]),
            Bin = ?DELIVER_SM(1234, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                        Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr,
                        ESMClass, RDFlag, Encode, LenTxt, Text),
            Length = byte_size(Bin),
            Bin1 = ?DELIVER_SM(Length, SeqNum, ServType, LenType, SaddrTon, 
                    SaddrNpi, Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, 
                    LenDaddr, ESMClass, RDFlag, Encode, LenTxt, Text),
			BinFin = case ESMClass of
				4 ->
					Bin2 = case proplists:get_value(message_state, List) of
						undefined -> Bin1;
						St ->
							add_msg_state(Bin1, St)
					end,
					case get_binary(receipted_message_id, List) of
						undefined -> Bin2;
						Id ->
							add_rmsg_id(Bin2, Id)
					end;
				_ -> Bin1
			end,
			io:format("FinalBin: ~p~n", [BinFin]),
			CorrectBin = correct_len(BinFin),
			io:format("CorrectBin: ~p~n", [CorrectBin]),
            [CorrectBin];
        true ->
            Tuple = cut_txt(Text, 1, MaxLen, []),
            SarRefNum = sar_ref_num(Param),
            assemble_submit(Tuple, SarRefNum, List, Param, Encode, [])
    end.        


submit_sm(List, Param) ->
    Handler = proplists:get_value(handler, Param), 
    Txt = get_binary(text, List),
    SeqNum = proplists:get_value(seq_n, Param),
    Daddr = get_binary(dest_addr, List),
    Saddr = get_binary(source_addr, List),
	RDFlag = get_binary(registered_delivery, List),
    {Encode, MaxLen} = exam_unicode(Txt, Param),
    Text = get_text_by_code(Encode, Txt),
    LenTxt = byte_size(Text),
    case LenTxt > MaxLen of
        false ->
            ServType = get_binary(service_type, Param),
            LenType = byte_size(ServType),
            LenDaddr = byte_size(Daddr),
            LenSaddr = byte_size(Saddr),
            SaddrTon = proplists:get_value(source_addr_ton, Param),
            SaddrNpi = proplists:get_value(source_addr_npi, Param),
            DaddrTon = proplists:get_value(dest_addr_ton, Param),
            DaddrNpi = proplists:get_value(dest_addr_npi, Param),
            ok = Handler:sequence_number_handler([{sequence_number, SeqNum}|List]),
            Bin = ?SUBMIT_SM(1234, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                        Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr,
                        RDFlag, Encode, LenTxt, Text),
            Length = byte_size(Bin),
            Bin1 = ?SUBMIT_SM(Length, SeqNum, ServType, LenType, SaddrTon, 
                    SaddrNpi, Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, 
                    LenDaddr, RDFlag, Encode, LenTxt, Text),
            [Bin1];
        true ->
            Tuple = cut_txt(Text, 1, MaxLen, []),
            SarRefNum = sar_ref_num(Param),
            assemble_submit(Tuple, SarRefNum, List, Param, Encode, [])
    end.        

data_sm(List, Param) -> 
    Daddr = get_binary(dest_addr, List),
    Txt = proplists:get_value(text, List),
    {Encode, _} = exam_unicode(Txt, Param),
    Text = get_text_by_code(Encode, Txt),
    LenTxt = byte_size(Text),
    SeqNum = proplists:get_value(seq_n, Param),
    ServType = get_binary(service_type, Param),
    LenType = byte_size(ServType),
    LenDaddr = byte_size(Daddr),
    Saddr = get_binary(source_addr, List),
    LenSaddr = byte_size(Saddr),
    SaddrTon = proplists:get_value(source_addr_ton, Param),
    SaddrNpi = proplists:get_value(source_addr_npi, Param),
    DaddrTon = proplists:get_value(dest_addr_ton, Param),
    DaddrNpi = proplists:get_value(dest_addr_npi, Param),
    Bin = ?DATA_SM(1234, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                    Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr, Encode, Text, LenTxt),
    Length = byte_size(Bin),
    ?DATA_SM(Length, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                 Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr, Encode, Text, LenTxt).

data_sm_resp(List) ->    
    SeqNum = proplists:get_value(sequence_number, List),
    Status = proplists:get_value(status, List),
    MsgId = proplists:get_value(message_id, List),
    LenId = byte_size(MsgId),
    Bin = ?DATA_SM_RESP(1234, Status, SeqNum, MsgId, LenId),
    Length = byte_size(Bin),
    ?DATA_SM_RESP(Length, Status, SeqNum, MsgId, LenId).

deliver_sm_resp(List) -> 
    SeqNum = proplists:get_value(sequence_number, List),
    Status = proplists:get_value(status, List),
    Bin = ?DELIVER_SM_RESP(1234, Status, SeqNum),
    Length = byte_size(Bin),
    ?DELIVER_SM_RESP(Length, Status, SeqNum).

query_sm(List, Param) ->
    SeqNum = proplists:get_value(seq_n, Param),
    MsgId = proplists:get_value(message_id, List),
    Len = byte_size(MsgId),
    Saddr = get_binary(source_addr, List),
    LenSaddr = byte_size(Saddr),
    SaddrTon = proplists:get_value(source_addr_ton, Param),
    SaddrNpi = proplists:get_value(source_addr_npi, Param),
    Bin = ?QUERY_SM(1234, SeqNum, MsgId, Len, SaddrTon, 
            SaddrNpi, Saddr, LenSaddr),
    Length = byte_size(Bin),
    ?QUERY_SM(Length, SeqNum, MsgId, Len, SaddrTon, 
            SaddrNpi, Saddr, LenSaddr).

enquire_link(Param) ->    
    SeqNum = proplists:get_value(seq_n, Param),
    ?ENQUIRE_LINK(SeqNum).

enquire_link_resp(List) ->
    SeqNum = proplists:get_value(sequence_number, List),
    ?ENQUIRE_LINK_RESP(SeqNum).

cancel_sm(List, Param) ->
    SeqNum = proplists:get_value(seq_n, Param),
    MsgId = proplists:get_value(message_id, List),
    LenId = byte_size(MsgId),
    Saddr = get_binary(source_addr, List),
    LenSaddr = byte_size(Saddr),
    SaddrTon = proplists:get_value(source_addr_ton, Param),
    SaddrNpi = proplists:get_value(source_addr_npi, Param),
    DaddrTon = proplists:get_value(dest_addr_ton, Param),
    DaddrNpi = proplists:get_value(dest_addr_npi, Param),
    Daddr = get_binary(dest_addr, List),
    LenDaddr = byte_size(Daddr),
    Bin = ?CANCEL_SM(1234, SeqNum, MsgId, LenId, SaddrTon, SaddrNpi, Saddr, 
                LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr),
    Length = byte_size(Bin),
    ?CANCEL_SM(Length, SeqNum, MsgId, LenId, SaddrTon, SaddrNpi, Saddr, 
                LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr).

replace_sm(List, Param) ->
    SeqNum = proplists:get_value(seq_n, Param),
    MsgId = proplists:get_value(message_id, List),
    LenId = byte_size(MsgId),
    Saddr = get_binary(source_addr, List),
    LenS = byte_size(Saddr),
    SaddrTon = proplists:get_value(source_addr_ton, Param),
    SaddrNpi = proplists:get_value(source_addr_npi, Param),
    Txt = get_binary(text, List),
    LenTxt = byte_size(Txt),
    Bin = ?REPLACE_SM(1234, SeqNum, MsgId, LenId, SaddrTon, SaddrNpi, 
                        Saddr, LenS, LenTxt, Txt),
    Length = byte_size(Bin),
    ?REPLACE_SM(Length, SeqNum, MsgId, LenId, SaddrTon, SaddrNpi, Saddr,
                        LenS, LenTxt, Txt).

assemble_submit({_SarTotSeg, []}, _SarRefNum, _List, _Param, _Encode, Acc) ->
    lists:reverse(Acc);
assemble_submit({SarTotSeg, [H|T]}, SarRefNum, List, Param, Encode, Acc) ->
    {SarSegNum, Chunk} = H,
    Handler = proplists:get_value(handler, Param), 
    Daddr = get_binary(dest_addr, List),
    SeqNum = proplists:get_value(seq_n, Param),
    ServType = get_binary(service_type, Param),
    LenType = byte_size(ServType),
    LenDaddr = byte_size(Daddr),
    LenChunk = byte_size(Chunk),
    LenMsg = LenChunk+6,
    Saddr = get_binary(source_addr, List),
    LenSaddr = byte_size(Saddr),
    SaddrTon = proplists:get_value(source_addr_ton, Param),
    SaddrNpi = proplists:get_value(source_addr_npi, Param),
    DaddrTon = proplists:get_value(dest_addr_ton, Param),
    DaddrNpi = proplists:get_value(dest_addr_npi, Param),
    NewList = lists:keyreplace(text, 1, List, {text, Chunk}),
    ok = Handler:sequence_number_handler([{sequence_number, SeqNum}|NewList]),
    Bin = ?SUBMIT_SM_CUT(1234, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr,
                Encode, LenMsg, Chunk, LenChunk, SarRefNum, SarSegNum, SarTotSeg),
    Length = byte_size(Bin),
    Bin1 = ?SUBMIT_SM_CUT(Length, SeqNum, ServType, LenType, SaddrTon, SaddrNpi, 
                    Saddr, LenSaddr, DaddrTon, DaddrNpi, Daddr, LenDaddr,
                    Encode, LenMsg, Chunk, LenChunk, SarRefNum, SarSegNum, SarTotSeg),
    Param1 = lists:keyreplace(seq_n, 1, Param, {seq_n, SeqNum+1}),
    assemble_submit({SarTotSeg, T}, SarRefNum, List, Param1, Encode, [Bin1|Acc]).

get_text_by_code(Encode, Bin) ->
    case Encode of 
        0 ->
            _GsmBin = esmpp_lib_latin1_to_gsm:latin1_to_gsm(Bin, <<>>);
        8 ->
	        _NewBin = unicode:characters_to_binary(Bin, utf8, utf16);
        _ ->
            Bin    
    end.

exam_unicode(Bin, Param) ->
    Latin1 = binary_to_list(Bin),
    Utf = unicode:characters_to_list(Bin),
    case Latin1 =/= Utf of 
        true ->
	        {8, 140};
        false ->
            Num = proplists:get_value(data_coding, Param),
            case Num of 
                undefined -> {0, 160};
	            0 -> {0, 160};
                3 -> {3, 140};
	            1 -> {1, 140};
	            2 -> {2, 140};
	            4 -> {4, 140};
	            5 -> {5, 140};
	            6 -> {6, 140};
	            7 -> {7, 140};
	            9 -> {9, 140};
	            10 -> {10, 140};
	            13 -> {13, 140};
	            14 -> {14, 140}
            end
    end.

convert_smpp_version(Param) ->
    case is_integer(Param) of
        false ->
            case Param of
                <<"3.4">> -> 52;
                <<"5.0">> -> 80
            end;
        true ->
            Param
    end.         

sar_ref_num(Param) ->
    Sar = proplists:get_value(sar, Param),
    WorkerPid = proplists:get_value(worker_pid, Param),
    case Sar of
	 255->
        WorkerPid ! {update_state, {sar, 0}},
	    1;
	Key ->
	    Key1 = Key + 1,
        WorkerPid ! {update_state, {sar, Key1}},
	    Key1
    end.
 
cut_txt(Text, Num, MaxLen, Acc) ->
    ChunkLen = case MaxLen of
        160 -> 153;
        140 -> 134
    end,
    case byte_size(Text) =< ChunkLen of
        true ->
            Len = 1 + length(Acc),
            {Len, lists:reverse([{Num, Text}|Acc])};
        false ->
            <<Chunk:ChunkLen/binary, Rest/binary>> = Text,
            cut_txt(Rest, Num+1, MaxLen, [{Num, Chunk}|Acc])
    end.


get_binary(Name, List) ->
    Param = proplists:get_value(Name, List),
    case is_integer(Param) of
        true -> 
            Param;
        false ->
            case is_binary(Param) of
                true -> Param;
                false -> list_to_binary(Param)
            end
    end.    
            
                   
add_msg_state(Bin, Val) ->
	<<Bin/binary, 1063:16/integer, 0, 1, Val:8/integer>>.

add_rmsg_id(Bin, Val) ->
	Len = byte_size(Val),
	FLen = Len + 1,
	<<Bin/binary, 30:16/integer, FLen:16/integer, Val:Len/binary, 0>>.

correct_len(<<_:32, Rest/binary>> = All) ->
	Len = byte_size(All),
	<<Len:32/integer, Rest/binary>>.
