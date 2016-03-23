
/** **********************************************************
 ****h* Nharu library/ICP-Brasil
 *  **********************************************************
 * NAME
 *	ICP-Brasil
 *
 * AUTHOR
 *	Copyleft (C) 2016 by The Crypthing Initiative
 *
 * PURPOSE
 *	ICP-Brasil Subject Alternative Names extensions implementation
 *
 * NOTES
 *	See http://www.iti.gov.br/images/legislacao/Docicp/DOC_ICP_04_V6.0_.pdf
 *
 * SEE ALSO
 *	NH_PKIBR_EXTENSION
 *	NH_parse_pkibr_extension
 *	NH_release_pkibr_extension
 *
 ******
 *
 *  ***********************************************************
 */

#ifndef __PKIBR_H__
#define __PKIBR_H__

#include "pkix.h"


/*
 ****t* ICP-Brasil/NH_PKIBR_EXTENSION
 *
 * NAME
 *	NH_PKIBR_EXTENSION
 *
 * PURPOSE
 *	ICP-Brasil certificates handler
 *
 * SYNOPSIS
 */
typedef struct NH_PKIBR_EXTENSION_STR
{
	NH_ASN1_PARSER_HANDLE	hParser;
	NH_ASN1_PNODE		subject_id;
	NH_ASN1_PNODE		sponsor_name;
	NH_ASN1_PNODE		company_id;
	NH_ASN1_PNODE		sponsor_id;
	NH_ASN1_PNODE		subject_te;
	NH_ASN1_PNODE		subject_cei;
	NH_ASN1_PNODE		company_cei;
	NH_ASN1_PNODE		company_name;

} NH_PKIBR_EXTENSION_STR, *NH_PKIBR_EXTENSION;
/*
 * INPUTS
 *	subject_id	-	OID = 2.16.76.1.3.1 e conteúdo nas primeiras 8 (oito) posições, a data de nascimento do titular,
 *				no formato ddmmaaaa; nas 11 (onze) posições subsequentes, o Cadastro de Pessoa Física (CPF) do
 *				titular; nas 11 (onze) posições subsequentes, o Número de Identificação Social - NIS (PIS, PASEP
 *				ou CI); nas 15 (quinze) posições subsequentes, o número do Registro Geral - RG do titular; nas 6
 *				(seis) posições subsequentes, as siglas do órgão expedidor do RG e respectiva UF.
 *	sponsor_name-	OID = 2.16.76.1.3.2 e conteúdo nome do responsável pelo certificado;
 *	company_id	-	OID = 2.16.76.1.3.3 e conteúdo nas 14 (quatorze) posições o número do Cadastro Nacional de Pessoa
 *				Jurídica (CNPJ) da pessoa jurídica titular do certificado
 *	sponsor_id	-	OID = 2.16.76.1.3.4 e conteúdo nas primeiras 8 (oito) posições, a data de nascimento do responsável
 *				pelo certificado, no formato ddmmaaaa; nas 11 (onze) posições subsequentes, o Cadastro de Pessoa
 *				Física (CPF) do responsável; nas 11 (onze) posições subsequentes, o número de Identificação Social
 *				– NIS (PIS, PASEP ou CI); nas 15 (quinze) posições subsequentes, o número do RG do responsável;
 *				nas 6 (seis) posições subsequentes, as siglas do órgão expedidor do RG e respectiva UF.
 *	subject_te	-	OID = 2.16.76.1.3.5 e conteúdo nas primeiras 12 (doze) posições, o número de inscrição do Título
 *				de Eleitor; nas 3 (três) posições subsequentes, a Zona Eleitoral; nas 4 (quatro) posições seguintes,
 *				a Seção; nas 22 (vinte e duas) posições subsequentes, o município e a UF do Título de Eleitor.
 *	subject_cei	-	OID = 2.16.76.1.3.6 e conteúdo nas 12 (doze) posições o número do Cadastro Especifico do INSS
 *				(CEI) da pessoa física titular do certificado
 *	company_cei	-	OID = 2.16.76.1.3.7 e conteúdo nas 12 (doze) posições o número do Cadastro Especifico do INSS
 *				(CEI) da pessoa jurídica titular do certificado
 *	company_name-	OID = 2.16.76.1.3.8 e conteúdo nome empresarial constante do CNPJ (Cadastro Nacional de Pessoa
 *				Jurídica), sem abreviações, se o certificado for de pessoa jurídica
 *
 * REMARKS
 *	PF:			subject_id && subject_te && subject_cei
 *	PJ:			sponsor_id && sponsor_name && company_id && company_cei
 *	URL:			company_name && company_id && sponsor_name && sponsor_id
 *
 *******/


#if defined(__cplusplus)
extern "C" {
#endif

/*
 ****f* ICP-Brasil/NH_parse_pkibr_extension
 *
 * NAME
 *	NH_parse_pkibr_extension
 *
 * PURPOSE
 *	Parses the ICP-Brasil fields from  this Subject Alternative Names extension value child SEQUENCE.
 *
 * ARGUMENTS
 *	_IN_ unsigned char *buffer: DER encoded extension value. This buffer is not copied and must not be freed before handler release.
 *	_IN_ size_t size: size of buffer
 *	_OUT_ NH_PKIBR_EXTENSION *hHandler: the handler itself
 *
 * RESULT
 *
 *
 * NOTES
 *	See RFC 5280
 *
 ******
 *
 */
NH_FUNCTION(NH_RV, NH_parse_pkibr_extension)(_IN_ unsigned char*, _IN_ size_t, _OUT_ NH_PKIBR_EXTENSION*);

/*
 ****f* ICP-Brasil/NH_release_pkibr_extension
 *
 * NAME
 *	NH_release_pkibr_extension
 *
 * PURPOSE
 *	Releases ICP-Brasil extension handler
 *
 * ARGUMENTS
 *	_INOUT_ NH_PKIBR_EXTENSION hHandler: the handler itself
 *
 ******
 *
 */
NH_FUNCTION(void, NH_release_pkibr_extension)(_INOUT_ NH_PKIBR_EXTENSION);


#if defined(__cplusplus)
}
#endif


#endif /* __PKIBR_H__ */
