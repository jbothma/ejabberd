%%%----------------------------------------------------------------------
%%% File    : ejabberd_s2s_in.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Serve incoming s2s connection
%%% Created :  6 Dec 2002 by Alexey Shchepin <alexey@process-one.net>
%%%
%%%
%%% ejabberd, Copyright (C) 2002-2011   ProcessOne
%%%
%%% This program is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This program is distributed in the hope that it will be useful,
%%% but WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this program; if not, write to the Free Software
%%% Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
%%% 02111-1307 USA
%%%
%%%----------------------------------------------------------------------

-module(ejabberd_s2s_in).
-author('alexey@process-one.net').

-behaviour(gen_fsm).

%% External exports
-export([start/2,
	 start_link/2,
	 socket_type/0]).

%% gen_fsm callbacks
-export([init/1,
	 wait_for_stream/2,
	 wait_for_feature_request/2,
	 stream_established/2,
	 handle_event/3,
	 handle_sync_event/4,
	 code_change/4,
	 handle_info/3,
	 terminate/3]).

-include("ejabberd.hrl").
-include("jlib.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("XmppAddr.hrl").

-define(DICT, dict).

-record(state, {socket,
		sockmod,
		streamid,
		shaper,
		tls = false,
		tls_enabled = false,
		tls_required = false,
		tls_certverify = false,
		tls_options = [],
		server,
		authenticated = false,
		auth_domain,
	        connections = ?DICT:new(),
		timer}).


%-define(DBGFSM, true).

-ifdef(DBGFSM).
-define(FSMOPTS, [{debug, [trace]}]).
-else.
-define(FSMOPTS, []).
-endif.

%% Module start with or without supervisor:
-ifdef(NO_TRANSIENT_SUPERVISORS).
-define(SUPERVISOR_START, gen_fsm:start(ejabberd_s2s_in, [SockData, Opts],
					?FSMOPTS)).
-else.
-define(SUPERVISOR_START, supervisor:start_child(ejabberd_s2s_in_sup,
						 [SockData, Opts])).
-endif.

-define(STREAM_HEADER(Version),
	(<<"<?xml version='1.0'?>"
	 "<stream:stream "
	 "xmlns:stream='http://etherx.jabber.org/streams' "
	 "xmlns='jabber:server' "
	 "xmlns:db='jabber:server:dialback' "
	 "id='", (StateData#state.streamid)/binary, "'", Version/binary, ">">>)
       ).

-define(STREAM_TRAILER, <<"</stream:stream>">>).

-define(INVALID_NAMESPACE_ERR,
	xml:element_to_binary(?SERR_INVALID_NAMESPACE)).

-define(HOST_UNKNOWN_ERR,
	xml:element_to_binary(?SERR_HOST_UNKNOWN)).

-define(INVALID_FROM_ERR,
        xml:element_to_binary(?SERR_INVALID_FROM)).

-define(INVALID_XML_ERR,
	xml:element_to_binary(?SERR_XML_NOT_WELL_FORMED)).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start(SockData, Opts) ->
    ?SUPERVISOR_START.

start_link(SockData, Opts) ->
    gen_fsm:start_link(ejabberd_s2s_in, [SockData, Opts], ?FSMOPTS).

socket_type() ->
    xml_stream.

%%%----------------------------------------------------------------------
%%% Callback functions from gen_fsm
%%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%% Func: init/1
%% Returns: {ok, StateName, StateData}          |
%%          {ok, StateName, StateData, Timeout} |
%%          ignore                              |
%%          {stop, StopReason}
%%----------------------------------------------------------------------
init([{SockMod, Socket}, Opts]) ->
    ?DEBUG("started: ~p", [{SockMod, Socket}]),
    Shaper = case lists:keysearch(shaper, 1, Opts) of
		 {value, {_, S}} -> S;
		 _ -> none
	     end,
    {StartTLS, TLSRequired, TLSCertverify} =
        case ejabberd_config:get_local_option(s2s_use_starttls) of
             UseTls when (UseTls==undefined) or (UseTls==false) ->
                 {false, false, false};
             UseTls when (UseTls==true) or (UseTls==optional) ->
                 {true, false, false};
             required ->
                 {true, true, false};
             required_trusted ->
                 {true, true, true}
         end,
    TLSCertfileOpt = case ejabberd_config:get_local_option(s2s_certfile) of
		  undefined -> [];
		  CertFile -> [{certfile, CertFile}]
	      end,
    TLSCACertfile = ejabberd_config:get_local_option(cacertfile),
    {TLSVerifyOpt, TLSCACertfileOpt} = case TLSCertverify of
                       false -> {[{verify, verify_none}],[]};
                       true ->
                           {[{verify, verify_peer}, {fail_if_no_peer_cert, true}],
                            [{cacertfile, TLSCACertfile}]}
                   end,
    TLSOpts = TLSCertfileOpt ++ TLSVerifyOpt ++ TLSCACertfileOpt,
    Timer = erlang:start_timer(?S2STIMEOUT, self(), []),
    {ok, wait_for_stream,
     #state{socket = Socket,
	    sockmod = SockMod,
	    streamid = new_id(),
	    shaper = Shaper,
	    tls = StartTLS,
	    tls_enabled = false,
	    tls_required = TLSRequired,
            tls_certverify = TLSCertverify,
	    tls_options = TLSOpts,
	    timer = Timer}}.

%%----------------------------------------------------------------------
%% Func: StateName/2
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------

wait_for_stream({xmlstreamstart, _Name, Attrs}, StateData) ->
    case {xml:get_attr_s(<<"xmlns">>, Attrs),
	  xml:get_attr_s(<<"xmlns:db">>, Attrs),
	  xml:get_attr_s(<<"to">>, Attrs),
	  xml:get_attr_s(<<"version">>, Attrs) == <<"1.0">>} of
	{<<"jabber:server">>, _, Server, true} when
	      StateData#state.tls and (not StateData#state.authenticated) ->
	    send_text(StateData, ?STREAM_HEADER(<<" version='1.0'">>)),
	    SASL =
		if
                    %% Only offer SASL EXT. if verifying peer cert.
		    StateData#state.tls_enabled
                    and StateData#state.tls_certverify ->
                        [{xmlelement, <<"mechanisms">>,
                          [{<<"xmlns">>, ?NS_SASL}],
                          [{xmlelement, <<"mechanism">>, [],
                            [{xmlcdata, <<"EXTERNAL">>}]}]}];
		    true ->
			[]
		end,
	    StartTLS = if
			   StateData#state.tls_enabled ->
			       [];
			   (not StateData#state.tls_enabled) and (not StateData#state.tls_required) ->
			       [{xmlelement, <<"starttls">>, [{<<"xmlns">>, ?NS_TLS}], []}];
			   (not StateData#state.tls_enabled) and StateData#state.tls_required ->
			       [{xmlelement, <<"starttls">>, [{<<"xmlns">>, ?NS_TLS}],
						[{xmlelement, <<"required">>, [], []}]
					   }]
		       end,
            send_element(StateData,
                         {xmlelement, <<"stream:features">>, [],
                          SASL ++ StartTLS ++
                              ejabberd_hooks:run_fold(
                                s2s_stream_features,
                                Server,
                                [], [Server])}),
            {next_state, wait_for_feature_request, StateData#state{server = Server}};
	{<<"jabber:server">>, _, Server, true} when
	      StateData#state.authenticated ->
	    send_text(StateData, ?STREAM_HEADER(<<" version='1.0'">>)),
	    send_element(StateData,
			 {xmlelement, <<"stream:features">>, [],
			  ejabberd_hooks:run_fold(
			    s2s_stream_features,
			    Server,
			    [], [Server])}),
	    {next_state, stream_established, StateData};
	{<<"jabber:server">>, <<"jabber:server:dialback">>, _Server, _} ->
	    send_text(StateData, ?STREAM_HEADER(<<"">>)),
	    {next_state, stream_established, StateData};
	_ ->
	    send_text(StateData, ?INVALID_NAMESPACE_ERR),
	    {stop, normal, StateData}
    end;

wait_for_stream({xmlstreamerror, _}, StateData) ->
    send_text(StateData,
	      <<(?STREAM_HEADER(<<"">>))/binary, (?INVALID_XML_ERR)/binary, (?STREAM_TRAILER)/binary>>),
    {stop, normal, StateData};

wait_for_stream(timeout, StateData) ->
    {stop, normal, StateData};

wait_for_stream(closed, StateData) ->
    {stop, normal, StateData}.


wait_for_feature_request({xmlstreamelement, El}, StateData) ->
    {xmlelement, Name, Attrs, Els} = El,
    TLS = StateData#state.tls,
    TLSEnabled = StateData#state.tls_enabled,
    SockMod = (StateData#state.sockmod):get_sockmod(StateData#state.socket),
    case {xml:get_attr_s(<<"xmlns">>, Attrs), Name} of
	{?NS_TLS, <<"starttls">>} when TLS == true,
				   TLSEnabled == false,
				   SockMod == gen_tcp ->
	    ?DEBUG("starttls", []),
	    Socket = StateData#state.socket,
	    TLSOpts = case ejabberd_config:get_local_option(
			     {domain_certfile,
			      StateData#state.server}) of
			  undefined ->
			      StateData#state.tls_options;
			  CertFile ->
			      [{certfile, CertFile} |
			       lists:keydelete(
				 certfile, 1,
				 StateData#state.tls_options)]
		      end,
	    TLSSocket = (StateData#state.sockmod):starttls(
			  receiver, Socket, TLSOpts,
			  xml:element_to_binary(
			    {xmlelement, <<"proceed">>, [{<<"xmlns">>, ?NS_TLS}], []})),
	    {next_state, wait_for_stream,
	     StateData#state{socket = TLSSocket,
			     streamid = new_id(),
			     tls_enabled = true,
			     tls_options = TLSOpts
			    }};
	{?NS_SASL, <<"auth">>} when TLSEnabled ->
	    Mech = xml:get_attr_s(<<"mechanism">>, Attrs),
	    case Mech of
		<<"EXTERNAL">> ->
		    Auth = jlib:decode_base64(xml:get_cdata(Els)),
		    AuthDomain = jlib:nameprep(Auth),
		    AuthRes =
			case (StateData#state.sockmod):get_peer_certificate(
			       StateData#state.socket) of
			    {ok, Cert} ->
                                ejabberd_tls:domain_matches_cert(AuthDomain, Cert);
                            {error, no_peercert} ->
                                ?WARNING_MSG("no peer cert from ~p in SASL EXT",
                                             [AuthDomain]),
                                false
			end,
		    if
			AuthRes ->
			    (StateData#state.sockmod):reset_stream(
			      StateData#state.socket),
			    send_element(StateData,
					 {xmlelement, <<"success">>,
					  [{<<"xmlns">>, ?NS_SASL}], []}),
			    ?DEBUG("(~w) Accepted s2s authentication for ~s",
				      [StateData#state.socket, AuthDomain]),
			    {next_state, wait_for_stream,
			     StateData#state{streamid = new_id(),
					     authenticated = true,
					     auth_domain = AuthDomain
					    }};
			true ->
                            ?INFO_MSG("SASL EXTERNAL failed for ~p", [AuthDomain]),
			    send_element(StateData,
					 {xmlelement, <<"failure">>,
					  [{<<"xmlns">>, ?NS_SASL}], []}),
			    send_text(StateData, ?STREAM_TRAILER),
			    {stop, normal, StateData}
		    end;
		_ ->
		    send_element(StateData,
				 {xmlelement, <<"failure">>,
				  [{<<"xmlns">>, ?NS_SASL}],
				  [{xmlelement, <<"invalid-mechanism">>, [], []}]}),
		    {stop, normal, StateData}
	    end;
	_ ->
	    stream_established({xmlstreamelement, El}, StateData)
    end;

wait_for_feature_request({xmlstreamend, _Name}, StateData) ->
    send_text(StateData, ?STREAM_TRAILER),
    {stop, normal, StateData};

wait_for_feature_request({xmlstreamerror, _}, StateData) ->
    send_text(StateData, <<(?INVALID_XML_ERR)/binary, (?STREAM_TRAILER)/binary>>),
    {stop, normal, StateData};

wait_for_feature_request(closed, StateData) ->
    {stop, normal, StateData}.


stream_established({xmlstreamelement, El}, StateData) ->
    cancel_timer(StateData#state.timer),
    Timer = erlang:start_timer(?S2STIMEOUT, self(), []),
    case is_key_packet(El) of
	{key, To, From, Id, Key} ->
	    ?DEBUG("GET KEY: ~p", [{To, From, Id, Key}]),
	    LTo = jlib:nameprep(To),
	    LFrom = jlib:nameprep(From),
	    %% Checks if the from domain is allowed and if the to
            %% domain is handled by this server:
            case {ejabberd_s2s:allow_host(LTo, LFrom),
                  lists:member(LTo, ejabberd_router:dirty_get_all_domains())} of
                {true, true} ->
		    ejabberd_s2s_out:terminate_if_waiting_delay(LTo, LFrom),
		    ejabberd_s2s_out:start(LTo, LFrom,
					   {verify, self(),
					    Key, StateData#state.streamid}),
		    Conns = ?DICT:store({LFrom, LTo}, wait_for_verification,
					StateData#state.connections),
		    change_shaper(StateData, LTo, jlib:make_jid(<<"">>, LFrom, <<"">>)),
		    {next_state,
		     stream_established,
		     StateData#state{connections = Conns,
				     timer = Timer}};
		{_, false} ->
		    send_text(StateData, ?HOST_UNKNOWN_ERR),
		    {stop, normal, StateData};
                {false, _} ->
                    send_text(StateData, ?INVALID_FROM_ERR),
                    {stop, normal, StateData}
	    end;
	{verify, To, From, Id, Key} ->
	    ?DEBUG("VERIFY KEY: ~p", [{To, From, Id, Key}]),
	    LTo = jlib:nameprep(To),
	    LFrom = jlib:nameprep(From),
	    Type = case ejabberd_s2s:has_key({LTo, LFrom}, Key) of
		       true -> <<"valid">>;
		       _ -> <<"invalid">>
		   end,
	    %Type = if Key == Key1 -> "valid";
	    % true -> "invalid"
	    % end,
	    send_element(StateData,
			 {xmlelement,
			  <<"db:verify">>,
			  [{<<"from">>, To},
			   {<<"to">>, From},
			   {<<"id">>, Id},
			   {<<"type">>, Type}],
			  []}),
	    {next_state, stream_established, StateData#state{timer = Timer}};
	_ ->
	    NewEl = jlib:remove_attr(<<"xmlns">>, El),
	    {xmlelement, Name, Attrs, _Els} = NewEl,
	    From_s = xml:get_attr_s(<<"from">>, Attrs),
	    From = jlib:binary_to_jid(From_s),
	    To_s = xml:get_attr_s(<<"to">>, Attrs),
	    To = jlib:binary_to_jid(To_s),
	    if
		(To /= error) and (From /= error) ->
		    LFrom = From#jid.lserver,
		    LTo = To#jid.lserver,
		    if
			StateData#state.authenticated ->
			    case (LFrom == StateData#state.auth_domain)
				andalso
				lists:member(
				  LTo,
				  ejabberd_router:dirty_get_all_domains()) of
				true ->
				    if ((Name == <<"iq">>) or
					(Name == <<"message">>) or
					(Name == <<"presence">>)) ->
					    ejabberd_hooks:run(
					      s2s_receive_packet,
					      LTo,
					      [From, To, NewEl]),
					    ejabberd_router:route(
					      From, To, NewEl);
				       true ->
					    error
				    end;
				false ->
				    error
			    end;
			true ->
			    case ?DICT:find({LFrom, LTo},
					    StateData#state.connections) of
				{ok, established} ->
				    if ((Name == <<"iq">>) or
					(Name == <<"message">>) or
					(Name == <<"presence">>)) ->
					    ejabberd_hooks:run(
					      s2s_receive_packet,
					      LTo,
					      [From, To, NewEl]),
					    ejabberd_router:route(
					      From, To, NewEl);
				       true ->
					    error
				    end;
				_ ->
				    error
			    end
		    end;
		true ->
		    error
	    end,
	    ejabberd_hooks:run(s2s_loop_debug, [{xmlstreamelement, El}]),
	    {next_state, stream_established, StateData#state{timer = Timer}}
    end;

stream_established({valid, From, To}, StateData) ->
    send_element(StateData,
		 {xmlelement,
		  <<"db:result">>,
		  [{<<"from">>, To},
		   {<<"to">>, From},
		   {<<"type">>, <<"valid">>}],
		  []}),
    LFrom = jlib:nameprep(From),
    LTo = jlib:nameprep(To),
    NSD = StateData#state{
	    connections = ?DICT:store({LFrom, LTo}, established,
				      StateData#state.connections)},
    {next_state, stream_established, NSD};

stream_established({invalid, From, To}, StateData) ->
    send_element(StateData,
		 {xmlelement,
		  <<"db:result">>,
		  [{<<"from">>, To},
		   {<<"to">>, From},
		   {<<"type">>, <<"invalid">>}],
		  []}),
    LFrom = jlib:nameprep(From),
    LTo = jlib:nameprep(To),
    NSD = StateData#state{
	    connections = ?DICT:erase({LFrom, LTo},
				      StateData#state.connections)},
    {next_state, stream_established, NSD};

stream_established({xmlstreamend, _Name}, StateData) ->
    {stop, normal, StateData};

stream_established({xmlstreamerror, _}, StateData) ->
    send_text(StateData,
	      <<(?INVALID_XML_ERR)/binary, (?STREAM_TRAILER)/binary>>),
    {stop, normal, StateData};

stream_established(timeout, StateData) ->
    {stop, normal, StateData};

stream_established(closed, StateData) ->
    {stop, normal, StateData}.



%%----------------------------------------------------------------------
%% Func: StateName/3
%% Returns: {next_state, NextStateName, NextStateData}            |
%%          {next_state, NextStateName, NextStateData, Timeout}   |
%%          {reply, Reply, NextStateName, NextStateData}          |
%%          {reply, Reply, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}                          |
%%          {stop, Reason, Reply, NewStateData}
%%----------------------------------------------------------------------
%state_name(Event, From, StateData) ->
%    Reply = ok,
%    {reply, Reply, state_name, StateData}.

%%----------------------------------------------------------------------
%% Func: handle_event/3
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
handle_event(_Event, StateName, StateData) ->
    {next_state, StateName, StateData}.
%%----------------------------------------------------------------------
%% Func: handle_sync_event/4
%% Returns: The associated StateData for this connection
%%   {reply, Reply, NextStateName, NextStateData}
%%   Reply = {state_infos, [{InfoName::atom(), InfoValue::any()]
%%----------------------------------------------------------------------
handle_sync_event(get_state_infos, _From, StateName, StateData) ->
    SockMod = StateData#state.sockmod,
    {Addr,Port} = try SockMod:peername(StateData#state.socket) of
		      {ok, {A,P}} ->  {A,P};
		      {error, _} -> {unknown,unknown}
		  catch
		      _:_ -> {unknown,unknown}
		  end,
    Domains =	case StateData#state.authenticated of
		    true ->
			[StateData#state.auth_domain];
		    false ->
			Connections = StateData#state.connections,
			[D || {{D, _}, established} <-
			    dict:to_list(Connections)]
		end,
    Infos = [
	     {direction, in},
	     {statename, StateName},
	     {addr, Addr},
	     {port, Port},
	     {streamid, StateData#state.streamid},
	     {tls, StateData#state.tls},
	     {tls_enabled, StateData#state.tls_enabled},
	     {tls_options, StateData#state.tls_options},
	     {authenticated, StateData#state.authenticated},
	     {shaper, StateData#state.shaper},
	     {sockmod, SockMod},
	     {domains, Domains}
	    ],
    Reply = {state_infos, Infos},
    {reply,Reply,StateName,StateData};

%%----------------------------------------------------------------------
%% Func: handle_sync_event/4
%% Returns: {next_state, NextStateName, NextStateData}            |
%%          {next_state, NextStateName, NextStateData, Timeout}   |
%%          {reply, Reply, NextStateName, NextStateData}          |
%%          {reply, Reply, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}                          |
%%          {stop, Reason, Reply, NewStateData}
%%----------------------------------------------------------------------
handle_sync_event(_Event, _From, StateName, StateData) ->
    Reply = ok,
    {reply, Reply, StateName, StateData}.

code_change(_OldVsn, StateName, StateData, _Extra) ->
    {ok, StateName, StateData}.

%%----------------------------------------------------------------------
%% Func: handle_info/3
%% Returns: {next_state, NextStateName, NextStateData}          |
%%          {next_state, NextStateName, NextStateData, Timeout} |
%%          {stop, Reason, NewStateData}
%%----------------------------------------------------------------------
handle_info({send_text, Text}, StateName, StateData) ->
    send_text(StateData, Text),
    {next_state, StateName, StateData};

handle_info({timeout, Timer, _}, _StateName,
	    #state{timer = Timer} = StateData) ->
    {stop, normal, StateData};

handle_info(_, StateName, StateData) ->
    {next_state, StateName, StateData}.


%%----------------------------------------------------------------------
%% Func: terminate/3
%% Purpose: Shutdown the fsm
%% Returns: any
%%----------------------------------------------------------------------
terminate(Reason, _StateName, StateData) ->
    ?DEBUG("terminated: ~p", [Reason]),
    (StateData#state.sockmod):close(StateData#state.socket),
    ok.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------

send_text(StateData, Text) ->
    (StateData#state.sockmod):send(StateData#state.socket, Text).

send_element(StateData, El) ->
    send_text(StateData, xml:element_to_binary(El)).


change_shaper(StateData, Host, JID) ->
    Shaper = acl:match_rule(Host, StateData#state.shaper, JID),
    (StateData#state.sockmod):change_shaper(StateData#state.socket, Shaper).


new_id() ->
    list_to_binary(randoms:get_string()).

cancel_timer(Timer) ->
    erlang:cancel_timer(Timer),
    receive
	{timeout, Timer, _} ->
	    ok
    after 0 ->
	    ok
    end.


is_key_packet({xmlelement, Name, Attrs, Els}) when Name == <<"db:result">> ->
    {key,
     xml:get_attr_s(<<"to">>, Attrs),
     xml:get_attr_s(<<"from">>, Attrs),
     xml:get_attr_s(<<"id">>, Attrs),
     xml:get_cdata(Els)};
is_key_packet({xmlelement, Name, Attrs, Els}) when Name == <<"db:verify">> ->
    {verify,
     xml:get_attr_s(<<"to">>, Attrs),
     xml:get_attr_s(<<"from">>, Attrs),
     xml:get_attr_s(<<"id">>, Attrs),
     xml:get_cdata(Els)};
is_key_packet(_) ->
    false.

