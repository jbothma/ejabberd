%%%-------------------------------------------------------------------
%%% File    : ejabberd_auth_ldap_pool.erl
%%% Author  : Evgeniy Khramtsov <xram@jabber.ru>
%%% Purpose : LDAP connections pool
%%% Created : 12 Nov 2006 by Evgeniy Khramtsov <xram@jabber.ru>
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
%%%-------------------------------------------------------------------

-module(ejabberd_ldap_pool).
-author('xram@jabber.ru').

%% API
-export([child_specs/7,
         eldap_start_function/7,
         start_group/2,
         bind/4,
         search/3,
         modify_passwd/4
        ]).

-include("ejabberd.hrl").

%%====================================================================
%% API
%%====================================================================

child_specs(GroupPrefix, VHost, LDAPServers, Port, RootDN, RootPwd, TLSOpts) ->
    GroupName = group_name(GroupPrefix, VHost),
    [{conn_name(GroupPrefix, VHost, LDAPServer),
      {?MODULE, eldap_start_function,
       [GroupName, conn_name(GroupPrefix, VHost, LDAPServer),
        LDAPServer, Port, RootDN, RootPwd, TLSOpts]},
      permanent, 2000, worker, [eldap, ?MODULE]}
     || LDAPServer <- LDAPServers].

%% Start via this function rather than eldap:start_link since the pool
%% members should be added to the pg2 group relating to the pool
eldap_start_function(GroupName, ConnName, LDAPServer, Port, RootDN, RootPwd,
                     TLSOpts) ->
    {ok, Pid} =
        eldap:start_link(ConnName, LDAPServer, Port, RootDN, RootPwd, TLSOpts),
    pg2:join(GroupName, Pid),
    {ok, Pid}.

start_group(GroupPrefix, VHost) ->
    pg2:create(group_name(GroupPrefix, VHost)).

bind(GroupType, VHost, DN, Passwd) ->
    do_request(GroupType, VHost, {bind, [DN, Passwd]}).

search(GroupType, VHost, Opts) ->
    do_request(GroupType, VHost, {search, [Opts]}).

modify_passwd(GroupType, VHost, DN, Passwd) ->
    do_request(GroupType, VHost, {modify_passwd, [DN, Passwd]}).

%%====================================================================
%% Internal functions
%%====================================================================
do_request(GroupPrefix, VHost, {F, Args}) ->
    GroupName = group_name(GroupPrefix, VHost),
    case pg2:get_closest_pid(GroupName) of
        Pid when is_pid(Pid) ->
            case catch apply(eldap, F, [Pid | Args]) of
                {'EXIT', {timeout, _}} ->
                    ?ERROR_MSG("LDAP request failed: timed out", []);
                {'EXIT', Reason} ->
                    ?ERROR_MSG("LDAP request failed: eldap:~p(~p)~nReason: ~p",
                               [F, Args, Reason]),
                    {error, Reason};
                Reply ->
                    ?DEBUG("~p eldap:~p(~p) -> ~p",
                           [GroupName, F, Args, Reply]),
                    Reply
            end;
        Err ->
            ?WARNING_MSG("No available eldap connection for group ~p to perform"
                         "eldap:~p(~p) on: ~p",
                         [GroupName, F, Args, Err]),
            Err
    end.


group_name(Prefix, VHost) ->
    list_to_atom(
      "eldap_" ++ atom_to_list(Prefix) ++ "_pool_" ++ binary_to_list(VHost)).

conn_name(Prefix, VHost, LDAPServer) ->
    list_to_atom(
      "eldap_" ++ atom_to_list(Prefix)
      ++ "_" ++ binary_to_list(VHost)
      ++ "_" ++ binary_to_list(LDAPServer)).
