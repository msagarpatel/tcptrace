typedef union	{ /* the types that we use in the tokens */
    char *string;
    long signed_long;
    u_long unsigned_long;
    ipaddr *pipaddr;
    Bool bool;
    enum optype op;
    struct filter_node *pf;
} YYSTYPE;
#define	EOS	258
#define	LPAREN	259
#define	RPAREN	260
#define	GREATER	261
#define	GREATER_EQ	262
#define	LESS	263
#define	LESS_EQ	264
#define	EQUAL	265
#define	NEQUAL	266
#define	NOT	267
#define	AND	268
#define	OR	269
#define	BAND	270
#define	BOR	271
#define	PLUS	272
#define	MINUS	273
#define	TIMES	274
#define	DIVIDE	275
#define	MOD	276
#define	VARIABLE	277
#define	STRING	278
#define	SIGNED	279
#define	UNSIGNED	280
#define	BOOL	281
#define	IPADDR	282


extern YYSTYPE filtyylval;
