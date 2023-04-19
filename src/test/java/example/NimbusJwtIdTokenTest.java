package example;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;

/**
 * Encrypted id_token was captured with
 * https://github.com/psteniusubi/python-sample
 * 
 * This example uses JWT library from
 * https://bitbucket.org/connect2id/nimbus-jose-jwt/src/master/
 */
public class NimbusJwtIdTokenTest {
    // this id_token was captured with code-flow-with-jwsreq.py
    static String ID_TOKEN = "eyJjdHkiOiJKV1QiLCJhbGciOiJSU0EtT0FFUCIsImtpZCI6Ijc3OTllNzBhLTUzYzEtNDZjNi1iNGI1LTM5NzkwZGVlYTk5NyIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.FuVhmIdj2mOf9UPFPLbSeHKQIAUDvNVQxDV3X2MhE6MEiucD1tOLjRDMIuSPIVK9Co518OCvy-PskuMhxCPdmcCnbqI7YXa_ZZ2L2DATMM_nJNqpELuhn8SMEhXgmq9JHRQOu_FtejCr1T1pXL9-Jh8Qb49Ka9DnivqLqh388aZgmoIGOWg_kqF__qZgIRBsrw2L29aZX8GnzRkniUMXjy2-BkbpfdOWgEidvgZgDuBOZ5afaK32NOrkoTiSp_l2fbdo22R4A3v58T00es6ddTj1b1RAqi2nEmYwXRvw5OIsSFOToy-wdIaEetnSYigMPU675ZrRse-E4A8chZxHBQ.oqNpnfCf7swEHvK0c-7uYw.ScCiyQ8EsgOqblu3okL-_NC4Z9GBOIU3-ek97r264UETqp0lCgSswiTiQLZE0VAdd1WOZnXbAnvMmUGhdqhT5MFFSGNj0xCotOk-756EnJF2Dj2imNuSj4fC6CxnLAdjWXwv9zRUaWa30RkXai-zPEvLwGGuAUvS2waY5fP1ME0M60nnaYBxplNeRpATQDDBxt8kK_cI1t1yUh8PLk1iutIAx57niyvZutgzvh5m5FKGMEEfPndXNJ2s9FBYjWhlqU7-GEplvjoLo1o8Ial9Y9UXggp8j_0l_kdwvu1LG-F58vnuPWpE3UC03exonL0J3Z2NSsazEhxE2h5zZRl1Cy-680Msr9jCOyiMBrS68HB6GyOv1ThiDQjJaPfCA9IQj4_qTopBCmWH_rrXVu2IWD2CmbUKSZk6A1-djt7o-g8QdQVOG1omueTWchPqLjdyUJyNxbNxtu5V-JVXTY3T87uBXnnTeXb3hRbhehDqnZE84rvjwDqfyWnLZcGQmUtD6U3rkv7hEFdgr_3IMEQgknzO6FXl4VmXtXJJ39XNPvjfdBelt4b50xOG2leHCpWdhRsfaVRG0uoOX2taCGzRUKo93e3zq6qtdXOWPj6ciAlvS54OPTFOLeys-PMqPUO6jw8-_z23i4kpScAMvRNe09MyomkhRvQsdFv2KtRxwL1nLMp5KnqjuXKlDnHdgx8hsgild3vUSFAvTea_I_R2o4jvYyHGI-48uanFkyPI6hSmDbDIcR6pL5vAFNszIJ1RBMB2sDkWQN9yefH_g7ptPsTNLthgzixhxKLlI_v13WFIbICPJ1CtNecqi8KgF6_B5E1AzblLwe-a0q5Qn-wZRIyXNOYM58ccBrsbD-41c2y_WnXWjiP-E4aA0px3hDaBAyGqYoEX8fmKaheUUbrKsLOSU0H4Snsv5Acn2WsD_ELI8WfH_PKfj8ZNS425Zl3m3hnccHfkEg3WZp7LOttYmjazvFD6_GdzS52HLhP06k8w5ANfff044KhTQuztOJI-FND-p_coiPlzTXhA6QY4sK2pvtGa7SHEf4PUQv0v5ogv1FoIRRVz7J781pM7xz5V557R7bjb15us2HB84WROt73dxxvEBebW5-gIMtgbWORCnqZao7xRqRPcIq9mfaCkR95OKw2USEcWeWCOXvPrMTpBSy5pVmXvsm1gXm8Fb7ba_4f-eFt1zdmxdZwpnVOUrph-0G9EFsxivdHRFwZA3-eQgZ0m3NjdKufZRT1QmoSK_XNYF5SYcKBQZuaEI6l5XzeP7-PjMBAylWyZv_20jbJxSIFkM8j6PaOXp5NxSdwnGKq132AHq2hxXMRrEcbXWTedHxBNWHJmDdX_-UYthgnB32nzjPq-4s_j7PEDjkYUznHqBPTQwtJy4Rk7btchoAZuzSP8YWICNcEUUnorVC25H6S4RL-a2veRNNdMbn7SKTidUwxMtcsFfJRS_0LLrB5F1KHKHdDFFMIesSwGh8pZ9uycU1oNE4fD28O_wfJDvl-4QBYg3LHFvDS58vSiKGQQqf-PnHtJ8FhLzrJp8A7szZflqOGjltEXtw__gZ4.BhKXHyZqJW9pXMBqCfi8Yg";
    // this jwk is from code-flow-with-jwsreq.jwk
    static String JWKS = "{\"keys\":[{\"d\":\"Y6nY7tX6sKMPW3OErPjMgfzOr3lg2VlDA2M3tOyPwudvmWY0rBTdj6TLABzB8Qp4ceUY3ySV_BZ1jJFm3CeCAdKWGpgvUMLfVbRHyAIXs24MfaF32NQ28DrttrFMGDsRF0fQ-APIbWq1QPbIuXE6jA605Xzz5_tfJosmPFIkxYKa-6oi42htsCALn9amSjhwSleCRn_-bus5k-Q0qqbKxIacutCAQDwVHoQlAKGUiOJviiORk-2JJ7WJfi5TCz1nukL_h-Z41jrYZlap4rW8tP1BxfsrX6aBgjvw6aIyyfcLxXwViIseBlelsAXnCs4yb7twUcFSRg0D6MhPFqJ2AQ\",\"dp\":\"MJgSHIOcnF9rgQaeAYVj71UtG_Xz44OU4hkvM1KH3B6dxkQKE9vxktGs74KmkTd4UIOTIKtzFhD40P1magOyp4L2MW1VavY3UiY0WqjmBja16ODCz_qIq6FEx-AvSfWSoaPIAoMa1zmViyHsS7leMgBX6-euWS_TiJ0MnJEJdwk\",\"dq\":\"_VndWO7hnWiTze2NuIeGdhSw7vuat10G66IuUWa2gZKczFv-JpB_WNnI32pNoxZ4RGe9lUoeYK9QXGoCB1W7FsavbBzuzZ8YAFGwHKU1TkGVJkSwjVrC36mghVDdKKn3Iq3QMbP-8E1536zil-3NguTgjtiD5MYEwtU5THSj3Q\",\"e\":\"AQAB\",\"kid\":\"7799e70a-53c1-46c6-b4b5-39790deea997\",\"kty\":\"RSA\",\"n\":\"p7gJavUfzo1bfnD16ADMbd2clWdkCnqcsPK3KoT5Xs-9iKmjJN_hG5Je5s8ATRInGhFR2vYKu4GxjuAnbNjcuNNaHiyo-PexEZaYsS6yT40lhQj53L1r8ML76KTvcdklWmfCJ67OeDzPRlZO_TnEqZsJY2dzTloT_wQUqepXPeYQ19k7L_14FB1Rnhq4x0PU-JudJL25HrtH459JAtrLQQ9lDfRqEt1IWnWP4TJTdajYpY4nyeOstGFEvMa1kvEaweoDEEkkjqXRiBras9IfDt2F26wsInydPHnr7gYMvvoANuPX5lzXCsPjoo-wogeiOrAZvGQsaRd_q7f4vmkdPw\",\"p\":\"z92OwWt5l4B5Yd3_Xgue1P4eh6D0x39p2MSngBqnb5ukt1zKlE9s8Hb28mALj3tJ3uF3bIkCrpxpbwkYs_VzdpyGnWzXJrV3KJyjsltpAHai-T54WerbbTFh2dGzrN61agatgxn4yYTMzHGLocncd0dL4VDCX-nBakNKkPZTckk\",\"q\":\"zo6ObeYY58cWL7LW8wXoWVxAa1oevE4O6BR2_gdc3f2mnvU7Hc37CUCD2dgxxm73Uj331nHlo7ZfbQbStHU0hh7L-8JT5_5JEXUl2sS-vLW3xS2GYD1m6YR8ErR98PCcXxk7aZfMWEtYMdsdkcjiMXw9g9m9v9PnKXVjkn2BE0c\",\"qi\":\"z3xH8CwVgc1-znLP6yvZiBPn5L5jRYz5cttcQ4urIbtL8x_u3p9exZZHuTvlvxVctrK5a19SjUdbODT0LGaq1VWltiN1YFOpiE9Kf6NQnSiluxA8otTiPT8Tl0ZVtsr0l2hByzVKgUuyx6Xyy5pTBbEwgn2L7xuHXSunVLR_xxI\",\"use\":\"enc\"},{\"d\":\"bnBGJlUeAXzPgTL1O4TYWfrrU2fIPZ39BRfZFp4WV6V2IJ5loLBaAhUh_JJ3-5IQLiXPDcIgF6YNxgw4dGp557CvtTlvKhgtE3PjaNhQR16KdR2ofRhUkuWKi14eJZwAzJf0mkylc0ey7nZBorRYNMYDF82lUFNKv8WDwxRgHhqp5BtDsZ-IqGLagq6kX8y3S62ecZYHD7l9lKvvnmUxeuxr_g4S5fSN3iWwcfKivV-QzObFL6QT298Vrjzt17G0Q5Wzw5poCsWMqZI5dp3HXnjjhfZmVEig2oNEowyZ_lSFmVgvX0Yz9q7LOxpC6epwhMFDu4ipo_l032T3geRufQ\",\"dp\":\"7Lg-WP27vM00ydedEuwxwyg2JDhCao_iT7AWb5eoybKF5U05c3l7Xw6i8AJna-Ku-mSCZkT8b66UOtVRVgC_gZujUfRptRf1s-3UgM0sdBcbR47rJYAN89_tCU_5QnmHJfWZtPw0NuGRjv9utR4x110oQuSS0FovpFRcljAXDP0\",\"dq\":\"wvAifQkofJDsR4gpJxL-Q6IiBJnWrjBy4ATAgQYMDmuoaOkKtPXwdzlySgAG5Kyfkf6WVc8kfrl5DapqucR_BG9o9O8oQYj3zSNkeiPWMyIU2q27QfbhGaJ5lXCzM_NselHv33YrothqtFp7VFPPXcQTnTjLIMT7qHulmbNNkjM\",\"e\":\"AQAB\",\"kid\":\"870c4fca-817e-4021-a90a-2e6a16fe1611\",\"kty\":\"RSA\",\"n\":\"vSjZg25Bb_-UFOrvNAhnBsJea0Uk8qP51qvysF7TH_ItA7QQZioTI0lt2ZYDIaWizV9lH-NnVXWOOK6jxnRInsU4OFCwwsU-rmAOG8pnJw7iogg9dtzkfXLFvPqH1FasBIchTO3wyQSmvhzj8ItzQ-4zyJSeH7sHGxQP0gYHjNdR5Gs_4mraJ8FnkCmUxu3ik3Mr4Fj1zA6DkaHBJSUwNrlzKoE-EUf_EAvEom2mRDmoSw7Ia0AtKpzJU3GK83gtIy6AD-WUFOBAI7N8KZWoJXWqeIU6coJwOXyIJ9FXdykqZDAuV5A5Xn22LpIqc-NXo8XwBWJSzfy2YmMwi45v0Q\",\"p\":\"97D7UjHVpnXudCUCdFxTR2VPwpY5k4BeCZLtsjAEtst2A6A5Byomqt79z9draezd-Vw4L7Qm5ZnA2Yug_lUvJt26bOY1SZGjwj-EdjWx8F5dEbC8KWibRALZM2nUPm6CWRrV3wQAkYd-Y0qMzKS6TXk77WHIJ-ERWSzjyLG8Boc\",\"q\":\"w4E71ljlJuchfC0d_mDy6fchGiwt5eneuebf-SF6zCBqw2O0Og-C4MnejMA60B8rQY2N1hyNYj-AqSBVQyHIuh_W5f_rIUjMFMaIMBPO9sR3CKP2_Qr0JsQyEOC-kVfuWLXofgsZSrAxoWladpiybU4kEe2kzDrj57lh8qkOFOc\",\"qi\":\"4F1U0-cPpeSOnZ-MIrJMC7-DfsyGZoq-vXN5SDK2wmHS7h1HhAQoypKTvvAHkRSplyImTo7M8vzz6txdXHAeYQaEiZiz05z4O3TA3W71Ky7sbx-RqbHFGIGd9m8LhVIV55rE31sQCq_NSMyf7V8wK_WtlfsVywAA-HDOiF3p8qg\",\"use\":\"sig\"}]}";
    // set to true when using captured id token
    static boolean TESTING = true;

    @Test
    public void test1() throws Exception {

        ConfigurableJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();

        // replace with id_token from OIDC token response 
        JWT token = JWTParser.parse(ID_TOKEN);

        if (token instanceof PlainJWT) {
            // plain not encrypted and/or unsigned token is not accepted
            throw new IllegalArgumentException();
        }
        if (token instanceof EncryptedJWT) {
            // if id token is encrypted then create JWEDecryptionKeySelector
            // replace JWKS with your application's keys
            JWKSet jwks = JWKSet.parse(JWKS);
            EncryptedJWT jwe = (EncryptedJWT) token;
            // make sure content type (cty) is JWT
            if(!"JWT".equals(jwe.getHeader().getContentType())) {
                throw new IllegalArgumentException();
            }
            JWEDecryptionKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
                    jwe.getHeader().getAlgorithm(), jwe.getHeader().getEncryptionMethod(), new ImmutableJWKSet<>(jwks));
            proc.setJWEKeySelector(jweKeySelector);
            // make sure token type (typ) is JWT
            proc.setJWETypeVerifier(DefaultJOSEObjectTypeVerifier.JWT);
        }

        // make sure token type (typ) is JWT
        proc.setJWSTypeVerifier(DefaultJOSEObjectTypeVerifier.JWT);

        // accept any RSA signature format
        Set<JWSAlgorithm> jwsAlgs = new HashSet<>(
                Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

        // fetch jwks from ID provider
        JWKSource<SecurityContext> jwsJwkSource = JWKSourceBuilder
                .create(new URL("https://login.example.ubidemo.com/uas/oauth2/metadata.jwks")).build();
        // create JWSVerificationKeySelector
        JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(jwsAlgs, jwsJwkSource);
        proc.setJWSKeySelector(jwsKeySelector);

        // allowed audience is client_id
        Set<String> audience = new HashSet<>(Arrays.asList("2af1c7c9-04dc-40d0-abac-103cee2a821d"));
        // validate iss claim
        JWTClaimsSet expected = new JWTClaimsSet.Builder().issuer("https://login.example.ubidemo.com/uas").build();
        if (TESTING) {
            // for testing, validate iss, iat and exp claims
            expected = new JWTClaimsSet.Builder().issuer("https://login.example.ubidemo.com/uas")
                    .issueTime(Date.from(Instant.ofEpochSecond(1681402772)))
                    .expirationTime(Date.from(Instant.ofEpochSecond(1681406371))).build();
        }
        // require sub, iat and exp claims be present
        Set<String> required = new HashSet<>(Arrays.asList("sub", "iat", "exp"));
        // no prohibited claims
        Set<String> prohibited = Collections.emptySet();

        // create DefaultJWTClaimsVerifier
        JWTClaimsSetVerifier<SecurityContext> verifier = new DefaultJWTClaimsVerifier<>(audience, expected, required,
                prohibited);
        if (TESTING) {
            // for testing, override currentTime
            verifier = new DefaultJWTClaimsVerifier<>(audience, expected, required, prohibited) {
                @Override
                protected Date currentTime() {
                    return Date.from(Instant.ofEpochSecond(1681402772));
                }
            };
        }
        proc.setJWTClaimsSetVerifier(verifier);

        // validate id token and get claims
        JWTClaimsSet claims = proc.process(token, null);
        assertNotNull(claims);
        assertEquals("https://login.example.ubidemo.com/uas", claims.getIssuer());

    }
}
