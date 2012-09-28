%%%----------------------------------------------------------------------
%%% File:    eldap_filter.erl
%%% Purpose: Converts String Representation of
%%%            LDAP Search Filter (RFC 2254)
%%%            to eldap's representation of filter
%%% Author:  Evgeniy Khramtsov <ekhramtsov@process-one.net>
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
-module(eldap_filter).

-export([parse/1, parse/2, do_sub/2]).

-define(MAX_RECURSION, 100).

%%====================================================================
%% API
%%====================================================================
%%%-------------------------------------------------------------------
%%% Arity: parse/1
%%% Function: parse(RFC2254_Filter) -> {ok, EldapFilter}   |
%%%                                    {error, bad_filter}
%%%
%%%           RFC2254_Filter = string().
%%%
%%% Description: Converts String Representation of LDAP Search Filter (RFC 2254)
%%%              to eldap's representation of filter.
%%%
%%% Example:
%%%   > eldap_filter:parse("(&(!(uid<=100))(mail=*))").
%%%
%%%   {ok,{'and',[{'not',{lessOrEqual,{'AttributeValueAssertion',"uid","100"}}},
%%%           {present,"mail"}]}}
%%%-------------------------------------------------------------------

parse(L) ->
    parse(L, []).

%%%-------------------------------------------------------------------
%%% Arity: parse/2
%%% Function: parse(RFC2254_Filter, [SubstValue |...]) ->
%%%                                  {ok, EldapFilter}                 |
%%%                                  {error, bad_filter}               |
%%%                                  {error, bad_regexp}               |
%%%                                  {error, max_substitute_recursion}
%%%
%%%           SubstValue = {RegExp, Value} | {RegExp, Value, N},
%%%           RFC2254_Filter = RegExp = Value = string(),
%%%           N = integer().
%%%
%%% Description: The same as parse/1, but substitutes N or all occurences
%%%              of RegExp with Value *after* parsing.
%%%
%%% Example:
%%%    > eldap_filter:parse(
%%%            "(|(mail=%u@%d)(jid=%u@%d))",
%%%            [{"%u", "xramtsov"},{"%d","gmail.com"}]).
%%%
%%%    {ok,{'or',[{equalityMatch,{'AttributeValueAssertion',
%%%                              "mail",
%%%                              "xramtsov@gmail.com"}},
%%%           {equalityMatch,{'AttributeValueAssertion',
%%%                              "jid",
%%%                              "xramtsov@gmail.com"}}]}}
%%%
%%%-------------------------------------------------------------------
parse(RFC2254_Filter, SList) when is_binary(RFC2254_Filter), is_list(SList) ->
    Tokens = scan(RFC2254_Filter, SList),
    case eldap_filter_yecc:parse(Tokens) of
	{error, {_, _, Msg}} ->
	    {error, Msg};
	{ok, Result} ->
	    {ok, Result};
	{regexp, Err} ->
	    {error, Err}
    end.

%%====================================================================
%% Internal functions
%%====================================================================
-define(do_scan(OpAtom), scan(Rest, <<>>, [{OpAtom, 1} | check(Buf, SubList) ++ Result], OpAtom, SubList)).

%% L = Filter string
%% SList = list of substitution tuples
scan(L, SubList) ->
    scan(L, <<>>, [], undefined, SubList).

%%
%% scan(<<Consumed, Rest>>, Buff, Result, SubstList) -> []
%%
scan(<<"=*)", Rest/binary>>, Buf, Result, '(',   SubList) ->
    scan(Rest, <<>>, [{')', 1}, {'=*', 1} | check(Buf, SubList) ++ Result], ')', SubList);
scan(<<":dn", Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan(':dn');
scan(<<":=",  Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan(':=');
scan(<<":=",  Rest/binary>>, Buf, Result, ':dn', SubList) -> ?do_scan(':=');
scan(<<":=",  Rest/binary>>, Buf, Result, ':',   SubList) -> ?do_scan(':=');
scan(<<"~=",  Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan('~=');
scan(<<">=",  Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan('>=');
scan(<<"<=",  Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan('<=');
scan(<<"=",   Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan('=');
scan(<<":",   Rest/binary>>, Buf, Result, '(',   SubList) -> ?do_scan(':');
scan(<<":",   Rest/binary>>, Buf, Result, ':dn', SubList) -> ?do_scan(':');
scan(<<"&",   Rest/binary>>, Buf, Result, '(',   SubList) when Buf==<<"">> -> ?do_scan('&');
scan(<<"|",   Rest/binary>>, Buf, Result, '(',   SubList) when Buf==<<"">> -> ?do_scan('|');
scan(<<"!",   Rest/binary>>, Buf, Result, '(',   SubList) when Buf==<<"">> -> ?do_scan('!');
scan(<<"*",   Rest/binary>>, Buf, Result, '*',   SubList) -> ?do_scan('*');
scan(<<"*",   Rest/binary>>, Buf, Result, '=',   SubList) -> ?do_scan('*');
scan(<<"(",   Rest/binary>>, Buf, Result, _,     SubList) -> ?do_scan('(');
scan(<<")",   Rest/binary>>, Buf, Result, _,     SubList) -> ?do_scan(')');
scan(<<Letter:8, Rest/binary>>, Buf, Result, PreviousAtom, SubList) ->
    scan(Rest, <<Buf/binary, Letter:8>>, Result, PreviousAtom, SubList);
scan(<<>>,                   Buf, Result, _,     SubList) ->
    lists:reverse(check(Buf, SubList) ++ Result).

check(<<>>, _) ->
    [];
check(Buf, S) ->
    [{str, 1, do_sub(Buf, S)}].

do_sub(S, []) ->
    S;

do_sub(<<>>, _) ->
    <<>>;

do_sub(S, [{RegExp, New} | T]) ->
    Result = do_sub(S, {RegExp, replace_specials(New)}, 1),
    do_sub(Result, T);

do_sub(S, [{RegExp, New, Times} | T]) ->
    Result = do_sub(S, {RegExp, replace_specials(New), Times}, 1),
    do_sub(Result, T).

do_sub(S, {RegExp, New}, Iter) ->
    case re:run(S, RegExp, [{capture, none}]) of
        match ->
            case re:replace(S, RegExp, New, [{return, binary}]) of
                NewS when Iter =< ?MAX_RECURSION ->
                    do_sub(NewS, {RegExp, New}, Iter+1);
                _NewS when Iter > ?MAX_RECURSION ->
                    erlang:error(max_substitute_recursion)
            end;
        nomatch ->
            S
    end;

do_sub(S, {_, _, N}, _) when N<1 ->
    S;

do_sub(S, {RegExp, New, Times}, Iter) ->
    case re:run(S, RegExp, [{capture, none}]) of
        match ->
            case re:replace(S, RegExp, New, [{return, binary}]) of
                NewS when Iter < Times ->
                    do_sub(NewS, {RegExp, New, Times}, Iter+1);
                NewS ->
                    NewS
            end;
        nomatch ->
            S
    end.

replace_specials(Subject) ->
    Subject1 = re:replace(Subject, "\\&", "\\\\&", [{return,binary}]),
    re:replace(Subject1, "\\\\", "\\\\", [{return,binary}]).
