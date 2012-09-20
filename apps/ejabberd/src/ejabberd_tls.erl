%%%----------------------------------------------------------------------
%%% Author  : Alexey Shchepin <alexey@process-one.net>
%%% Purpose : Check for matching domains in peer certificates
%%%
%%% Taken from ejabberd_2s_in.erl
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

-module(ejabberd_tls).

-export([domain_matches_cert/2]).

-include("ejabberd.hrl").
-include("jlib.hrl").
-include_lib("public_key/include/public_key.hrl").
-define(PKIXEXPLICIT, 'OTP-PUB-KEY').
-define(PKIXIMPLICIT, 'OTP-PUB-KEY').
-include("XmppAddr.hrl").

domain_matches_cert(error, _)->
    false;
domain_matches_cert(Domain, CertBin) when is_binary(Domain) andalso
                                          is_binary(CertBin)->
    Cert = public_key:pkix_decode_cert(CertBin, plain),
    case idna:domain_utf8_to_ascii(Domain) of
        false ->
            false;
        PCAuthDomain ->
            CertDomains = get_cert_domains(Cert),
            ?DEBUG("Domain: ~p  CertDomains: ~p", [Domain, CertDomains]),
            lists:any(fun(D) ->
                              match_domain(PCAuthDomain, D)
                      end,
                      CertDomains)
    end.

get_cert_domains(Cert = #'Certificate'{}) ->
    {rdnSequence, Subject} =
	(Cert#'Certificate'.tbsCertificate)#'TBSCertificate'.subject,
    Extensions =
	(Cert#'Certificate'.tbsCertificate)#'TBSCertificate'.extensions,
    lists:flatmap(
      fun(#'AttributeTypeAndValue'{type = ?'id-at-commonName',
				   value = Val}) ->
	      case ?PKIXEXPLICIT:decode('X520CommonName', Val) of
		  {ok, {_, D1}} ->
		      D = if
			      is_list(D1) -> list_to_binary(D1);
			      is_binary(D1) -> D1;
			      true -> error
			  end,
		      if
			  D /= error ->
			      case jlib:binary_to_jid(D) of
				  #jid{luser = <<"">>,
				       lserver = LD,
				       lresource = <<"">>} ->
				      [LD];
				  _ ->
				      []
			      end;
			  true ->
			      []
		      end;
		  _ ->
		      []
	      end;
	 (_) ->
	      []
      end, lists:flatten(Subject)) ++
	lists:flatmap(
	  fun(#'Extension'{extnID = ?'id-ce-subjectAltName',
			   extnValue = Val}) ->
		  BVal = if
			     is_list(Val) -> list_to_binary(Val);
			     is_binary(Val) -> Val;
			     true -> Val
			 end,
		  case ?PKIXIMPLICIT:decode('SubjectAltName', BVal) of
		      {ok, SANs} ->
			  lists:flatmap(
			    fun({otherName,
				 #'AnotherName'{'type-id' = ?'id-on-xmppAddr',
						value = XmppAddr
					       }}) ->
				    case 'XmppAddr':decode(
					   'XmppAddr', XmppAddr) of
					{ok, D} when is_binary(D) ->
					    case jlib:binary_to_jid(D) of
						#jid{luser = <<"">>,
						     lserver = LD,
						     lresource = <<"">>} ->
						    case idna:domain_utf8_to_ascii(LD) of
							false ->
							    [];
							PCLD ->
							    [PCLD]
						    end;
						_ ->
						    []
					    end;
					_ ->
					    []
				    end;
			       ({dNSName, D}) when is_list(D) ->
				    case jlib:binary_to_jid(list_to_binary(D)) of
					#jid{luser = <<"">>,
					     lserver = LD,
					     lresource = <<"">>} ->
					    [LD];
					_ ->
					    []
				    end;
			       (_) ->
				    []
			    end, SANs);
		      _ ->
			  []
		  end;
	     (_) ->
		  []
	  end, Extensions).

match_domain(Domain, Domain) ->
    true;
match_domain(Domain, Pattern) ->
    DLabels = binary:split(Domain, <<".">>, [global]),
    PLabels = binary:split(Pattern, <<".">>, [global]),
    match_labels(DLabels, PLabels).

match_labels([], []) ->
    true;
match_labels([], [_ | _]) ->
    false;
match_labels([_ | _], []) ->
    false;
match_labels([DL | DLabels], [PL | PLabels]) ->
    PLlist = binary_to_list(PL),
    case lists:all(fun(C) -> (($a =< C) andalso (C =< $z))
				 orelse (($0 =< C) andalso (C =< $9))
				 orelse (C == $-) orelse (C == $*)
		   end, PLlist) of
	true ->
	    Regexp = xmerl_regexp:sh_to_awk(PLlist),
	    case re:run(binary_to_list(DL), Regexp, [{capture, none}]) of
		match ->
		    match_labels(DLabels, PLabels);
		nomatch ->
		    false
	    end;
	false ->
	    false
    end.
