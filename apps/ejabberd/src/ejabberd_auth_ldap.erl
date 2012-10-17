%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_ldap.erl
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Authentification via LDAP
%%% Created : 12 Dec 2004 by Alexey Shchepin <alexey@process-one.net>
%%%
%%% Each vhost has a tree of ejabberd_auth_ldap_sup_VHost
%%%                          /       \                   \
%%%   ejabberd_auth_ldap_VHost   ejabberd_ldap_pool_sup   ejabberd_ldap_pool_sup
%%%                                              \                  \
%%%                                            eldap                eldap
%%%
%%% where ejabberd_auth_ldap caches the filter and connection configuration,
%%% and there's an ldap connection pool for LDAP bind operations and another for
%%% all other LDAP operations for each LDAP server.
%%% The bind and general eldap processes are in a bind or general pg2 group and
%%% a random process is chosen to complete each LDAP operation.
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

-module(ejabberd_auth_ldap).
-author('alexey@process-one.net').

-behaviour(gen_server).

%% ejabberd_auth_ exports
-export([start/1,
         set_password/3,
         check_password/3,
         check_password/5,
         try_register/3,
         dirty_get_registered_users/0,
         get_vh_registered_users/1,
         get_vh_registered_users_number/1,
         get_password/2,
         get_password_s/2,
         is_user_exists/2,
         remove_user/2,
         remove_user/3,
         plain_password_required/0
        ]).

%% config exports
-export([get_connection_info/1]).

%% gen_server callbacks
-export([init/1,
         start_link/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

-include("ejabberd.hrl").
-include_lib("eldap/include/eldap.hrl").

-define(LDAP_SEARCH_TIMEOUT, 5). % Timeout for LDAP search queries in seconds
-define(SERVER, ?MODULE).
-define(SUPMOD, ejabberd_auth_ldap_sup).

-record(state, {vhost,
                ldap_servers,
                port,
                tls_options,
                root_dn,
                root_password,
                base,
                uids,
                ufilter,
                sfilter,
                lfilter, %% Local filter (performed by ejabberd, not LDAP)
                local_filter_attrs = undefined,
                dn_filter,
                dn_filter_attrs
               }).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------

start(Host) ->
    %% start ejabberd_auth_ldap_sup_Host
    SupName = gen_mod:get_module_proc(Host, ?SUPMOD),
    ChildSpec = {
      SupName, {?SUPMOD, start_link, [SupName, Host]},
      permanent, 1000, supervisor, [?MODULE]
     },
    {ok, _SupPid} = supervisor:start_child(ejabberd_sup, ChildSpec),

    {ok, State} = get_state(Host),

    %% start ejabberd_ldap_pool_Type_Host
    BindPoolSupArgs = [bind,
                       Host,
                       State#state.ldap_servers,
                       State#state.port,
                       State#state.root_dn,
                       State#state.root_password,
                       State#state.tls_options],
    BindChildSpec = {
      ejabberd_ldap_pool_sup_bind,
      {ejabberd_ldap_pool_sup, start_link, BindPoolSupArgs},
      permanent, 2000, supervisor, [ejabberd_ldap_pool_sup]},
    {ok, _BindSupPid} = supervisor:start_child(SupName, BindChildSpec),
    GeneralPoolSupArgs = [general,
                          Host,
                          State#state.ldap_servers,
                          State#state.port,
                          State#state.root_dn,
                          State#state.root_password,
                          State#state.tls_options],
    GeneralChildSpec = {
      ejabberd_ldap_pool_sup_general,
      {ejabberd_ldap_pool_sup, start_link, GeneralPoolSupArgs},
      permanent, 2000, supervisor, [ejabberd_ldap_pool_sup]},
    {ok, _GeneralSupPid} = supervisor:start_child(SupName, GeneralChildSpec),
    ok.

plain_password_required() ->
    true.

check_password(User, Server, Password) ->
    %% In LDAP spec: empty password means anonymous authentication.
    %% As ejabberd is providing other anonymous authentication mechanisms
    %% we simply prevent the use of LDAP anonymous authentication.
    if Password == <<"">> ->
        false;
    true ->
        case catch check_password_ldap(User, Server, Password) of
            {'EXIT', _} = Err ->
                ?ERROR_MSG("~p inside ~p:check_password/3. returning false.~n",
                           [Err, ?MODULE]),
                false;
            Result -> Result
        end
    end.

check_password(User, Server, Password, _Digest, _DigestGen) ->
    check_password(User, Server, Password).

set_password(User, Server, Password) ->
    {ok, State} = get_state(Server),
    case find_user_dn(User, State) of
	false ->
	    {error, user_not_found};
	DN ->
	    ejabberd_ldap_pool:modify_passwd(general, Server, DN, Password)
    end.

%% @spec (User, Server, Password) -> {error, not_allowed}
try_register(_User, _Server, _Password) ->
    {error, not_allowed}.

dirty_get_registered_users() ->
    Servers = ejabberd_config:get_vh_by_auth_method(ldap),
    lists:flatmap(
      fun(Server) ->
	      get_vh_registered_users(Server)
      end, Servers).

get_vh_registered_users(Server) ->
    case catch get_vh_registered_users_ldap(Server) of
	{'EXIT', _} -> [];
	Result -> Result
	end.

get_vh_registered_users_number(Server) ->
    length(get_vh_registered_users(Server)).

get_password(_User, _Server) ->
    false.

get_password_s(_User, _Server) ->
    <<"">>.

%% @spec (User, Server) -> true | false | {error, Error}
is_user_exists(User, Server) ->
    case catch is_user_exists_ldap(User, Server) of
	{'EXIT', Error} ->
	    {error, Error};
	Result ->
	    Result
    end.

remove_user(_User, _Server) ->
    {error, not_allowed}.

remove_user(_User, _Server, _Password) ->
    not_allowed.

%%%===================================================================
%%% Config gen_server
%%%===================================================================

start_link(Host) ->
    ProcName = gen_mod:get_module_proc(Host, ?MODULE),
    gen_server:start_link({local, ProcName}, ?MODULE, [Host], []).

get_connection_info(Server) ->
    Name = gen_mod:get_module_proc(Server, ?MODULE),
    gen_server:call(Name, get_connection_info).

init([Host]) ->
    State = parse_options(Host),
    {ok, State}.

handle_call(get_connection_info, _From,
            State = #state{ ldap_servers = LDAPServers,
                            port = Port,
                            tls_options = TLSOpts,
                            root_dn = RootDN,
                            root_password = RootPwd}) ->
    Reply = {connection_info, LDAPServers, Port, RootDN, RootPwd, TLSOpts},
    {reply, Reply, State};
handle_call(get_state, _From, State) ->
    {reply, {ok, State}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.
handle_info(_Info, State) ->
    {noreply, State}.
terminate(_Reason, _State) ->
    ok.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%----------------------------------------------------------------------
%%% Internal functions
%%%----------------------------------------------------------------------

get_state(Server) ->
    Name = gen_mod:get_module_proc(Server, ?MODULE),
    gen_server:call(Name, get_state).

check_password_ldap(User, Server, Password) ->
	{ok, State} = get_state(Server),
	case find_user_dn(User, State) of
	false ->
	    false;
	DN ->
	    case ejabberd_ldap_pool:bind(bind, Server, DN, Password) of
		ok -> true;
		_ -> false
	    end
	end.

get_vh_registered_users_ldap(Server) ->
    {ok, State} = get_state(Server),
    ResAttrs = result_attrs(State),
    case eldap_filter:parse(State#state.sfilter) of
		{ok, EldapFilter} ->
		    case ejabberd_ldap_pool:search(
                           general, Server, [{base, State#state.base},
                                            {filter, EldapFilter},
                                            {timeout, ?LDAP_SEARCH_TIMEOUT},
                                            {attributes, ResAttrs}]) of
			#eldap_search_result{entries = Entries} ->
			    lists:flatmap(ldap_entry_ejabberd_user_fun(State),
                                          Entries);
			_ ->
			    []
		    end;
		_ ->
		    []
	end.

ldap_entry_ejabberd_user_fun(#state{ vhost=Server,
                                     uids = UIDs } = State) ->
    fun(#eldap_entry{ attributes = Attrs,
                      object_name = DN}) ->
            case is_valid_dn(DN, Attrs, State) of
                false -> [];
                _ ->
                    case ejabberd_ldap_utils:find_ldap_attrs(UIDs, Attrs) of
                        <<"">> -> [];
                        {User, UIDFormat} ->
                            case ejabberd_ldap_utils:get_user_part(
                                   User, UIDFormat) of
                                {ok, U} ->
                                    case jlib:nodeprep(U) of
                                        error -> [];
                                        LU -> [{LU, jlib:nameprep(Server)}]
                                    end;
                                _ -> []
                            end
                    end
            end
    end.

is_user_exists_ldap(User, Server) ->
    {ok, State} = get_state(Server),
    case find_user_dn(User, State) of
        false -> false;
        _DN -> true
    end.


find_user_dn(User, State) ->
    ResAttrs = result_attrs(State),
    case eldap_filter:parse(State#state.ufilter, [{<<"%u">>, User}]) of
        {ok, Filter} ->
            SearchArgs = [{base, State#state.base},
                          {filter, Filter},
                          {attributes, ResAttrs}],
            case ejabberd_ldap_pool:search(
                   general, State#state.vhost, SearchArgs) of
                #eldap_search_result{
                   entries = [#eldap_entry{attributes = Attrs,
                                           object_name = DN}|_]} ->
                    dn_filter(DN, Attrs, State);
                Error ->
                    ?DEBUG("Searching for user with args ~p failed: ~p~n",
                           [SearchArgs, Error]),
                    false
            end;
        Error ->
            ?DEBUG("Parsing filter ~p with substitution ~p failed: ~p~n",
                   [State#state.ufilter, {<<"%u">>, User}, Error]),
            false
    end.

%% apply the dn filter and the local filter:
dn_filter(DN, Attrs, State) ->
    %% Check if user is denied access by attribute value (local check)
    case check_local_filter(Attrs, State) of
        false -> false;
        true -> is_valid_dn(DN, Attrs, State)
    end.

%% Check that the DN is valid, based on the dn filter
is_valid_dn(DN, _, #state{dn_filter = undefined}) ->
    DN;

is_valid_dn(DN, Attrs, State) ->
    DNAttrs = State#state.dn_filter_attrs,
    UIDs = State#state.uids,
    Values = [{<<"%s">>, ejabberd_ldap_utils:get_ldap_attr(Attr, Attrs), 1}
              || Attr <- DNAttrs],
    SubstValues = case ejabberd_ldap_utils:find_ldap_attrs(UIDs, Attrs) of
		      <<"">> -> Values;
		      {S, UAF} ->
			  case ejabberd_ldap_utils:get_user_part(S, UAF) of
			      {ok, U} -> [{<<"%u">>, U} | Values];
			      _ -> Values
			  end
		  end ++ [{<<"%d">>, State#state.vhost}, {<<"%D">>, DN}],
    case eldap_filter:parse(State#state.dn_filter, SubstValues) of
	{ok, EldapFilter} ->
	    case ejabberd_ldap_pool:search(
                   general, State#state.vhost, [{base, State#state.base},
                                                {filter, EldapFilter},
                                                {attributes, [<<"dn">>]}]) of
		#eldap_search_result{entries = [_|_]} ->
		    DN;
		_ ->
		    false
	    end;
	_ ->
	    false
    end.

%% The local filter is used to check an attribute in ejabberd
%% and not in LDAP to limit the load on the LDAP directory.
%% A local rule can be either:
%%    {equal, {<<"accountStatus">>,[<<"active">>]}}
%%    {notequal, {<<"accountStatus">>,[<<"disabled">>]}}
%% {ldap_local_filter, {notequal, {<<"accountStatus">>,[<<"disabled">>]}}}
check_local_filter(_Attrs, #state{lfilter = undefined}) ->
    true;
check_local_filter(Attrs, #state{lfilter = LocalFilters})
  when is_list(LocalFilters) ->
    lists:all(fun({Operation, FilterMatch}) ->
                   local_filter(Operation, Attrs, FilterMatch)
              end,
              LocalFilters);
check_local_filter(Attrs, {Operation, FilterMatch}) ->
    local_filter(Operation, Attrs, FilterMatch).

local_filter(equal, Attrs, FilterMatch) ->
    {Attr, Value} = FilterMatch,
    case lists:keysearch(Attr, 1, Attrs) of
        false -> false;
        {value,{Attr,Value}} -> true;
        _ -> false
    end;
local_filter(notequal, Attrs, FilterMatch) ->
    not local_filter(equal, Attrs, FilterMatch).

result_attrs(#state{uids = UIDs, dn_filter_attrs = DNFilterAttrs,
                   local_filter_attrs = LFilterAttrs}) ->
    lists:foldl(
      fun({UID}, Acc) ->
	      [UID | Acc];
	 ({UID, _}, Acc) ->
	      [UID | Acc]
      end, DNFilterAttrs ++ LFilterAttrs, UIDs).

%%%----------------------------------------------------------------------
%%% Auxiliary functions
%%%----------------------------------------------------------------------
parse_options(Host) ->
    LDAPServers =
        lists:map(fun erlang:list_to_binary/1,
                  ejabberd_config:get_local_option({ldap_servers, Host})),
    LDAPEncrypt = ejabberd_config:get_local_option({ldap_encrypt, Host}),
    LDAPTLSVerify = ejabberd_config:get_local_option({ldap_tls_verify, Host}),
    LDAPPort = ejabberd_config:get_local_option({ldap_port, Host}),
    RootDN = case ejabberd_config:get_local_option({ldap_rootdn, Host}) of
		 undefined -> <<"">>;
		 RDN -> list_to_binary(RDN)
	     end,
    Password = case ejabberd_config:get_local_option({ldap_password, Host}) of
		   undefined -> <<"">>;
		   Pass -> list_to_binary(Pass)
	       end,
    UIDs = case ejabberd_config:get_local_option({ldap_uids, Host}) of
	       undefined -> [{<<"uid">>, <<"%u">>}];
	       UI ->
                   UIBin = lists:map(fun ldap_uids_to_bin/1, UI),
                   ejabberd_ldap_utils:uids_domain_subst(Host, UIBin)
	   end,
    SubFilter = ejabberd_ldap_utils:generate_subfilter(UIDs),
    UserFilter = case ejabberd_config:get_local_option({ldap_filter, Host}) of
		     undefined -> SubFilter;
		     "" -> SubFilter;
		     F ->
                         FBin = list_to_binary(F),
                         <<"(&", SubFilter/binary, FBin/binary, ")">>
		 end,
    SearchFilter = eldap_filter:do_sub(UserFilter, [{<<"%u">>, <<"*">>}]),
    LDAPBase = list_to_binary(
                 ejabberd_config:get_local_option({ldap_base, Host})),
    {DNFilter, DNFilterAttrs} =
	case ejabberd_config:get_local_option({ldap_dn_filter, Host}) of
	    undefined ->
		{undefined, []};
	    {DNF, undefined} ->
		ldap_dn_filter_to_bin({DNF, []});
	    {DNF, DNFA} ->
		ldap_dn_filter_to_bin({DNF, DNFA})
	end,
    LocalFilter = ejabberd_config:get_local_option({ldap_local_filter, Host}),
    LocalFilterBin = ldap_local_filter_to_bin(LocalFilter),
    LFilterAttrs = get_lfilter_attrs(LocalFilterBin),
    #state{vhost = Host,
	   ldap_servers = LDAPServers,
	   port = LDAPPort,
	   tls_options = [{encrypt, LDAPEncrypt},
			  {tls_verify, LDAPTLSVerify}],
	   root_dn = RootDN,
	   root_password = Password,
	   base = LDAPBase,
	   uids = UIDs,
	   ufilter = UserFilter,
	   sfilter = SearchFilter,
	   lfilter = LocalFilterBin,
           local_filter_attrs = LFilterAttrs,
	   dn_filter = DNFilter,
	   dn_filter_attrs = DNFilterAttrs
	  }.

get_lfilter_attrs(undefined) ->
    [];
get_lfilter_attrs([]) ->
    [];
get_lfilter_attrs([{_, {Attr, _}}|Rest]) ->
    [Attr | get_lfilter_attrs(Rest)];
get_lfilter_attrs({_, {Attr, _}}) ->
    [Attr].

ldap_uids_to_bin({Attr}) ->
    {list_to_binary(Attr)};
ldap_uids_to_bin({Attr, Format}) ->
    {list_to_binary(Attr), list_to_binary(Format)}.

ldap_dn_filter_to_bin({Filter, FilterAttrs}) ->
    FilterAttrsBin = lists:map(fun erlang:list_to_binary/1, FilterAttrs),
    {list_to_binary(Filter), FilterAttrsBin}.

ldap_local_filter_to_bin(undefined) ->
    undefined;
ldap_local_filter_to_bin([]) ->
    [];
ldap_local_filter_to_bin([{Atom, {AttrName, AttrVals}}|Rest]) ->
    AttrValsBin = lists:map(fun erlang:list_to_binary/1, AttrVals),
    [{Atom, {list_to_binary(AttrName), AttrValsBin}}
     | ldap_local_filter_to_bin(Rest)].
