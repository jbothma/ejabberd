%%%-------------------------------------------------------------------
%%% @author JD Bothma <jan.bothma@erlang-solutions.com>
%%% @copyright (C) 2012, Erlang Solutions
%%% @doc
%%%
%%% @end
%%% Created :  6 Sep 2012 by JD Bothma <jan.bothma@erlang-solutions.com>
%%%-------------------------------------------------------------------

-define(REPORT(F, Type, Format, Args),
        error_logger:F([Type,
                        {module, ?MODULE},
                        {line, ?LINE},
                        io_lib:format(Format, Args)])).

-define(DEBUG(Format, Args), ok).
-define(INFO_MSG(Format, Args), ?REPORT(info_report, 'INFO', Format, Args)).
-define(WARNING_MSG(Format, Args), ?REPORT(warning_report, 'WARNING', Format, Args)).
-define(ERROR_MSG(Format, Args), ?REPORT(error_report, 'ERROR', Format, Args)).
-define(CRITICAL_MSG(Format, Args), ?REPORT(error_report, 'CRITICAL', Format, Args)).
