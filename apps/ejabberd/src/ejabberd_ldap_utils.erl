%%%----------------------------------------------------------------------
%%% File    : ejabberd_auth_ldap_utils.erl
%%% Author  : Mickael Remond <mremond@process-one.net>
%%% Purpose : ejabberd LDAP helper functions
%%% Created : 12 Oct 2006 by Mickael Remond <mremond@process-one.net>
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

-module(ejabberd_ldap_utils).
-author('mremond@process-one.net').

-export([generate_subfilter/1,
	 find_ldap_attrs/2,
	 get_ldap_attr/2,
	 usort_attrs/1,
	 get_user_part/2,
	 make_filter/2,
	 case_insensitive_match/2,
	 uids_domain_subst/2]).

-include_lib("eunit/include/eunit.hrl").

%% Generate an 'or' LDAP query on one or several attributes
%% If there is only one attribute
generate_subfilter([UID]) ->
    subfilter(UID);
%% If there is several attributes
generate_subfilter(UIDs) ->
    <<"(|", << <<(subfilter(UID))/binary>> || UID <- UIDs>>/binary, ")">>.

%% Subfilter for a single attribute
subfilter({UIDAttr, UIDAttrFormat}) ->
    <<"(", UIDAttr/binary, "=", UIDAttrFormat/binary, ")">>;
%% The default UiDAttrFormat is %u
subfilter({UIDAttr}) ->
    <<"(", UIDAttr/binary, "=", "%u)">>.

%% Not tail-recursive, but it is not very terribly.
%% It stops finding on the first not empty value.
find_ldap_attrs([{Attr} | Rest], Attributes) ->
    find_ldap_attrs([{Attr, <<"%u">>} | Rest], Attributes);
find_ldap_attrs([{Attr, Format} | Rest], Attributes) ->
    case get_ldap_attr(Attr, Attributes) of
	Value when is_binary(Value), Value /= <<"">> ->
	    {Value, Format};
	_ ->
	    find_ldap_attrs(Rest, Attributes)
    end;
find_ldap_attrs([], _) ->
    <<"">>.

get_ldap_attr(LDAPAttr, Attributes) ->
    Res = lists:filter(
	    fun({Name, _}) ->
		    case_insensitive_match(Name, LDAPAttr)
	    end, Attributes),
    case Res of
	[{_, [Value|_]}] -> Value;
	_ -> <<"">>
    end.


usort_attrs(Attrs) when is_list(Attrs) ->
    lists:usort(Attrs);
usort_attrs(_) ->
    [].

get_user_part(String, Pattern) ->
    case binary:match(Pattern, <<"%u">>) of
        nomatch -> {error, badmatch};
        {Start, Length} ->
            TailLen = byte_size(Pattern) - (Start + Length),
            StringHeadAndUserLen = byte_size(String) - TailLen,
            UserLen = StringHeadAndUserLen - Start,
            %% binary:part/2 returns the binary or crashes
            {ok, binary:part(String, {Start, UserLen})}
    end.

make_filter(Data, UIDs) ->
    NewUIDs = [{U, eldap_filter:do_sub(UF, [{<<"%u">>, <<"*%u*">>, 1}])} || {U, UF} <- UIDs],
    Filter = lists:flatmap(
	       fun({Name, [Value | _]}) ->
		       case Name of
			   <<"%u">> when Value /= <<"">> ->
			       case eldap_filter:parse(generate_subfilter(NewUIDs),
                                                       [{<<"%u">>, Value}]) of
				   {ok, F} -> [F];
				   _ -> []
			       end;
			   _ when Value /= <<"">> ->
			       [eldap:substrings(Name, [{any, Value}])];
			   _ ->
			       []
		       end
	       end, Data),
    case Filter of
	[F] ->
	    F;
	_ ->
	    eldap:'and'(Filter)
    end.

case_insensitive_match(X, Y) ->
    X1 = stringprep:tolower(X),
    Y1 = stringprep:tolower(Y),
    if
	X1 == Y1 -> true;
	true -> false
    end.

%% From the list of uids attribute:
%% we look from alias domain (%d) and make the substitution
%% with the actual host domain
%% This help when you need to configure many virtual domains.
uids_domain_subst(Host, UIDs) ->
    lists:map(fun({U,V}) ->
                      {U, eldap_filter:do_sub(V,[{<<"%d">>, Host}])};
                  (A) -> A
              end,
              UIDs).


%%======================================
%% eunit
%%======================================

get_user_part_test() ->
    ?assertEqual({ok, <<"john">>}, get_user_part(<<"john">>, <<"%u">>)),
    ?assertEqual({ok, <<"john">>}, get_user_part(<<"john@domain.com">>,
                                                 <<"%u@domain.com">>)),
    ?assertEqual({ok, <<"john">>}, get_user_part(<<"blahjohn@domain.com">>,
                                                 <<"blah%u@domain.com">>)).