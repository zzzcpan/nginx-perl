
This is more of ideas list than TODO, but still

    Accessing destroyed requests:
	Keep request's SV in ctx.
	    SvREFCNT_inc(sv);
	Add http cleanup handler and reset request's SV when it is destroyed:
	    sv_setiv(sv, 0);
	    SvREFCNT_dec(sv);
	And in XS make sure none of the functions do anything with request
	if it is NULL. Also issue warning message.
	This way when someone finalizes request more than once nothing happens.

	Also make sure to use the same SV when calling handler.

    Decide on removing G_EVAL. 

