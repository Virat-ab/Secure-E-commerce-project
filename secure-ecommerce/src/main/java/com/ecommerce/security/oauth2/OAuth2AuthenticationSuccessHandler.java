package com.ecommerce.security.oauth2;

import com.ecommerce.security.jwt.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * After successful OAuth2 login, generate JWT tokens and redirect
 * to the frontend callback URL with tokens as query parameters.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;

    private static final String REDIRECT_URI = "http://localhost:3000/oauth2/callback";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                         HttpServletResponse response,
                                         Authentication authentication) throws IOException {

        String tenantId = resolveTenantFromRequest(request);
        String accessToken = tokenProvider.generateAccessToken(authentication, tenantId);
        String refreshToken = tokenProvider.generateRefreshToken(
            authentication.getName(), tenantId);

        String redirectUrl = UriComponentsBuilder.fromUriString(REDIRECT_URI)
            .queryParam("accessToken", accessToken)
            .queryParam("refreshToken", refreshToken)
            .build().toUriString();

        log.info("OAuth2 success, redirecting user: {}", authentication.getName());
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    private String resolveTenantFromRequest(HttpServletRequest request) {
        String tenantHeader = request.getHeader("X-Tenant-ID");
        return (tenantHeader != null && !tenantHeader.isBlank()) ? tenantHeader : "public";
    }
}
