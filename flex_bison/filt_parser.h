typedef union	{ /* the types that we use in the tokens */
    char *string;
    long signed_long;
    u_long unsigned_long;
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
#define	PLUS	270
#define	MINUS	271
#define	TIMES	272
#define	DIVIDE	273
#define	MOD	274
#define	VARIABLE	275
#define	STRING	276
#define	SIGNED	277
#define	UNSIGNED	278
#define	BOOL	279


extern YYSTYPE filtyylval;
