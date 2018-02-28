-module(esmpp_lib_worker).
-author('Alexander Zhuk <aleksandr.zhuk@privatbank.ua>').

-behaviour(gen_server).
-define(SERVER, ?MODULE).

-include("esmpp_lib.hrl").

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/1]).
-export([submit/2, data_sm/2, unbind/1, query_sm/2, cancel_sm/2,
         replace_sm/2]).
-export([loop_tcp/6, enquire_link/1]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% Callback Function Definitions
%% ------------------------------------------------------------------

-callback submit_sm_resp_handler(pid(), list()) -> ok.
-callback data_sm_handler(pid(), list())        -> ok.
-callback data_sm_resp_handler(pid(), list())   -> ok.
-callback deliver_sm_handler(pid(), list())     -> ok.
-callback query_sm_resp_handler(pid(), list())  -> ok.
-callback unbind_handler(pid())                 -> ok.
-callback outbind_handler(pid(), term())        -> ok.
-callback network_error(pid(), term())          -> ok.
-callback decoder_error(pid(), term())          -> ok.
-callback submit_error(pid(), term())           -> ok.
-callback sequence_number_handler(list())       -> ok.

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link(Param) ->
    gen_server:start_link(?MODULE, Param, []).


-spec deliver(pid(), list()) -> ok.
deliver(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {deliver, List}),
    ?LOG_INFO("Send msg deliver ~p~n ", [List]).

-spec submit(pid(), list()) -> ok.
submit(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {submit, List}),
    ?LOG_INFO("Send msg submit ~p~n ", [List]).

-spec data_sm(pid(), list()) -> ok.
data_sm(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {data_sm, List}),
    ?LOG_INFO("Send msg data_sm ~p~n ", [List]).

-spec query_sm(pid(), list()) -> ok.
query_sm(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {query_sm, List}),
    ?LOG_INFO("Send msg query_sm ~p~n ", [List]).

-spec replace_sm(pid(), list()) -> ok.
replace_sm(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {replace_sm, List}),
    ?LOG_INFO("Send msg replace_sm ~p~n ", [List]).

-spec cancel_sm(pid(), list()) -> ok.
cancel_sm(WorkerPid, List) ->
    gen_server:cast(WorkerPid, {cancel_sm, List}),
    ?LOG_INFO("Send msg cancel_sm ~p~n ", [List]).

-spec unbind(pid()) -> ok.  
unbind(WorkerPid) ->
    gen_server:cast(WorkerPid, {unbind, []}),
    ?LOG_INFO("Send msg unbind for pid ~p~n ", [WorkerPid]).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init(Param) ->
    Mode = proplists:get_value(mode, Param),
    WorkerPid = self(),
    _ = erlang:send_after(10, WorkerPid, {bind, Mode}),
    {ok, ProcessingPid} = esmpp_lib_submit_processing:start_link([{parent_pid, WorkerPid}|Param]),
    Param1 = [{processing_pid, ProcessingPid}, {sar, 0}, {seq_n, 0}, {worker_pid, WorkerPid}|Param],            
    {ok, Param1}.

handle_call(Request, _From, State) ->
    ?LOG_ERROR("Unknown call request ~p~n", [Request]),
    {reply, ok, State}.

handle_cast({deliver, List}, State) ->   
    SmsList = esmpp_lib_encoder:encode(deliver_sm, State, List),
    State1 = send_sms(SmsList, State),
    {noreply, State1}; 
handle_cast({submit, List}, State) ->   
    SmsList = esmpp_lib_encoder:encode(submit_sm, State, List),
    State1 = send_sms(SmsList, State),
    {noreply, State1}; 
handle_cast({query_sm, List}, State) ->
    Transport = get_transport(State),
    Handler = proplists:get_value(handler, State),
    WorkerPid = proplists:get_value(worker_pid, State),
    Socket = proplists:get_value(socket, State),  
    Bin = esmpp_lib_encoder:encode(query_sm, State, List),
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    {noreply, accumulate_seq_num(State)}; 
handle_cast({replace_sm, List}, State) ->
    Transport = get_transport(State),
    Handler = proplists:get_value(handler, State),
    WorkerPid = proplists:get_value(worker_pid, State),
    Socket = proplists:get_value(socket, State),  
    Bin = esmpp_lib_encoder:encode(replace_sm, State, List),
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    {noreply, accumulate_seq_num(State)}; 
handle_cast({cancel_sm, List}, State) ->
    Handler = proplists:get_value(handler, State),
    WorkerPid = proplists:get_value(worker_pid, State),
    Transport = get_transport(State),
    Socket = proplists:get_value(socket, State),  
    Bin = esmpp_lib_encoder:encode(cancel_sm, State, List),
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    {noreply, accumulate_seq_num(State)}; 
handle_cast({data_sm, List}, State) ->
    SmsList = esmpp_lib_encoder:encode(data_sm, State, List),
    State1 = send_sms([SmsList], State),
    {noreply, State1}; 
handle_cast({unbind, []}, State) ->
    Transport = get_transport(State),
    Handler = proplists:get_value(handler, State),
    WorkerPid = proplists:get_value(worker_pid, State),
    Socket = proplists:get_value(socket, State),
    Bin = esmpp_lib_encoder:encode(unbind, State),
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    ok = Handler:unbind_handler(WorkerPid),
    WorkerPid ! {terminate, unbind},
    {noreply, accumulate_seq_num(State)}; 
handle_cast(Msg, State) ->
    ?LOG_ERROR("Unknown cast msg ~p~n", [Msg]),
    {noreply, State}.

handle_info({bind, Mode}, Param) ->
    Transport = get_transport(Param),
    WorkerPid = proplists:get_value(worker_pid, Param),
    ProcessingPid = proplists:get_value(processing_pid, Param),
    Handler = proplists:get_value(handler, Param),
    State1 = case bind(Mode, Param) of
        {error, Reason} ->
            ok = Handler:network_error(WorkerPid, Reason),
            WorkerPid ! {terminate, Reason},
            Param;
        Socket ->
            Param1 = accumulate_seq_num([{socket, Socket}|Param]),
            ListenPid = spawn_link(?MODULE, loop_tcp, [<<>>, Transport, Socket, WorkerPid, Handler, ProcessingPid]),
            case proplists:get_value(enquire_timeout, Param1) of
                undefined ->
                    ok;
                _ ->
                    _ = spawn_link(?MODULE, enquire_link, [Param1])
            end,
            [{mode, Mode},{listen_pid, ListenPid}|Param1]
    end,
    {noreply, State1};
handle_info({update_state, {Name, NewEntry}}, State) ->
    State1 = lists:keyreplace(Name, 1, State, {Name, NewEntry}),
    {noreply, State1};
handle_info({get_state, ListenPid}, State) ->
    ListenPid ! {state, State},
    {noreply, State};
handle_info({terminate, Reason}, State) ->
    {stop, Reason, State};
handle_info(Info, State) ->
    ?LOG_ERROR("Unknown info msg ~p~n", [Info]),
    {noreply, State}.

terminate(Reason, State) -> 
    ?LOG_CRITICAL("Process terminate with reason ~p state is ~p~n", [Reason, State]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

bind(Mode, Param) ->
    Transport = get_transport(Param),
    case connect(Param) of
        {error, Reason} ->
            {error, Reason};
        {_, Socket} ->
            Bin = esmpp_lib_encoder:encode(Mode, Param),
            Resp = Transport:send(Socket, Bin),
            case handle_bind(Resp, Socket, Transport) of
                ok ->
                    ?LOG_INFO("Socket ~p mode ~p~n", [Socket, Mode]),
                    Socket;
                {error, Reason} ->    
                    {error, Reason}
            end
    end. 

connect(Param) ->
    Transport = get_transport(Param),
    Ip = proplists:get_value(host, Param),
    Port = proplists:get_value(port, Param),
    _ = Transport:connect(Ip, Port, [binary, {active, false},
                        {keepalive, true}, {reuseaddr, true}, {packet, 0}], 2000).

handle_bind(Resp, Socket, Transport) ->
    case Resp of
        ok ->
            exam_bind_resp(Socket, Transport);
        {error, Reason} ->
            {error, Reason}
    end.

send_sms([], State) ->
    State;
send_sms([Bin|T], State) ->
    Transport = get_transport(State),
    WorkerPid = proplists:get_value(worker_pid, State),
    ProcessingPid = proplists:get_value(processing_pid, State),
    Socket = proplists:get_value(socket, State),
    Handler = proplists:get_value(handler, State),
    <<_:12/binary, SeqNum:32/integer, _/binary>> = Bin,
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    Ts = os:timestamp(),
    ProcessingPid ! {update_state, {add_submit, {SeqNum, {Handler, Ts, Socket}}}},
    send_sms(T, accumulate_seq_num(State)).

loop_tcp(Buffer, Transport, Socket, WorkerPid, Handler, ProcessingPid) ->
    case Transport:recv(Socket, 0) of 
        {ok, Bin} ->
            try esmpp_lib_decoder:decode(<<Buffer/bitstring, Bin/bitstring>>, []) of
                [{undefined, Name}|_] ->
                    ?LOG_WARNING("Unsupported smpp packet ~p~n", [Name]),
                    loop_tcp(<<>>, Transport, Socket, WorkerPid, Handler, ProcessingPid);
                List ->
                    ok = create_resp(List, Transport, Socket, WorkerPid, Handler, ProcessingPid),
                    loop_tcp(<<>>, Transport, Socket, WorkerPid, Handler, ProcessingPid)
            catch
                _Class:Reason ->
                    case byte_size(Bin)>1535 of
                        true ->
                            Handler:decoder_error(WorkerPid, Bin),                        
                            WorkerPid ! {terminate, Reason};
                        false ->
                            loop_tcp(<<Buffer/bitstring, Bin/bitstring>>, Transport, Socket, WorkerPid, Handler, ProcessingPid)
                    end
            end;
        {error, closed} ->
            ok = Handler:network_error(WorkerPid, closed),
            WorkerPid ! {terminate, closed};
        {error, Reason} ->
            ok = Handler:network_error(WorkerPid, Reason),
            WorkerPid ! {terminate, Reason}
    end.              

create_resp([], _Transport, _Socket, _WorkerPid, _Handler, _ProcessingPid) ->
    ok;
create_resp([H|T], Transport, Socket, WorkerPid, Handler, ProcessingPid) ->
	{Name, Code, SeqNum, List} = H,
    Resp = assemble_resp({Name, Code, SeqNum, List}, Socket, WorkerPid, Handler, ProcessingPid),
    case Resp of
        ok ->
            ok;
        {close_session, Bin} ->
            ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
            ok = Handler:network_error(WorkerPid, close_session);
        _ ->
            ok = try_send(Transport, Socket, Resp, WorkerPid, Handler)
    end,
    create_resp(T, Transport, Socket, WorkerPid, Handler, ProcessingPid).  

assemble_resp({Name, Status, SeqNum, List}, Socket, WorkerPid, Handler, ProcessingPid) ->
    case Name of
        enquire_link -> 
            esmpp_lib_encoder:encode(enquire_link_resp, [], [{sequence_number, SeqNum}]);
        enquire_link_resp ->
            ok; 
        deliver_sm -> 
            MsgId = proplists:get_value(receipted_message_id, List),
            ok = Handler:deliver_sm_handler(WorkerPid, [{sequence_number, SeqNum}, {command_status, Status}|List]),
            esmpp_lib_encoder:encode(deliver_sm_resp, [], [{sequence_number, SeqNum}, {message_id, MsgId}, {status, 0}]); 
        submit_sm_resp ->
            ProcessingPid ! {processing_submit, Handler, List, SeqNum, submit_sm_resp_handler, Status},
            ok; 
        data_sm_resp ->
            ProcessingPid ! {processing_submit, Handler, List, SeqNum, data_sm_resp_handler, Status},
            ok; 
        data_sm ->                                                                                  
            MsgId = proplists:get_value(receipted_message_id, List),
            ok = Handler:data_sm_handler(WorkerPid, [{sequence_number, SeqNum}, {command_status, Status}|List]),
            esmpp_lib_encoder:encode(data_sm_resp, [], [{sequence_number, SeqNum}, {message_id, MsgId}, {status, 0}]); 
        query_sm_resp ->
            ok = Handler:query_sm_resp_handler(WorkerPid, [{sequence_number, SeqNum}, {command_status, Status}|List]);
        alert_notification ->
            ok;
        outbind ->
            ok = Handler:outbind_handler(WorkerPid, Socket);
        generic_nack ->
            ?LOG_ERROR("Generic nack error code ~p~n", [Status]);
        unbind_resp ->
            ?LOG_ERROR("Unbind session ~p~n", [WorkerPid]),
            Bin = esmpp_lib_encoder:encode(unbind_resp, [], [{sequence_number, SeqNum}]),
            {close_session, Bin};
        unbind ->
            ?LOG_ERROR("Unbind session ~p~n", [WorkerPid]),
            Bin = esmpp_lib_encoder:encode(unbind_resp, [], [{sequence_number, SeqNum}]),
            {close_session, Bin}
    end.

exam_bind_resp(Socket, Transport) ->
    case Transport:recv(Socket, 0, 5000) of 
        {ok, Bin} ->
            [{_Name, Code, _SeqNum, _List}] = esmpp_lib_decoder:decode(Bin, []),
            case Code of 
                0 ->
                    ok;
                Resp ->
                    ?LOG_ERROR("Error bind packet code ~p ~n", [Code]),
                    {error, Resp}  
            end;
        {error, Reason} ->
            ?LOG_ERROR("Error bind, tcp connect fail ~p ~n", [Reason]),  
            {error, Reason}
    end.

enquire_link(State) ->
    EnquireTimeout = proplists:get_value(enquire_timeout, State)*1000,
    ok = timer:sleep(EnquireTimeout),
    Transport = get_transport(State),
    Socket = proplists:get_value(socket, State),
    WorkerPid = proplists:get_value(worker_pid, State),
    Handler = proplists:get_value(handler, State),
    Bin = esmpp_lib_encoder:encode(enquire_link, State),
    ok = try_send(Transport, Socket, Bin, WorkerPid, Handler),
    enquire_link(accumulate_seq_num(State)).                       
    
get_transport(Param) ->
    case proplists:get_value(transport, Param) of 
        tcp -> gen_tcp;
        undefined -> gen_tcp;
        ssl -> ssl
    end.
     
accumulate_seq_num(State) ->
    SeqNum = proplists:get_value(seq_n, State),
    Value = case SeqNum of 
        999999 ->
            1;
        SeqNum ->
            SeqNum + 1
    end,
    lists:keyreplace(seq_n, 1, State, {seq_n, Value}).
     
try_send(Transport, Socket, Bin, WorkerPid, Handler) -> 
    case Transport:send(Socket, Bin) of
        ok -> ok;
        {error, Reason} ->
            ok = Handler:network_error(WorkerPid, Reason),
            WorkerPid ! {terminate, Reason}, 
            ok
    end. 
