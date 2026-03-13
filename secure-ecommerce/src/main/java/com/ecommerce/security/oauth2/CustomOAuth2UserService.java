package com.ecommerce.security.oauth2;

import com.ecommerce.model.entity.User;
import com.ecommerce.model.enums.AuthProvider;
import com.ecommerce.model.enums.UserStatus;
import com.ecommerce.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = delegate.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId(); // google | github
        String email = extractEmail(oAuth2User, provider);
        String providerId = oAuth2User.getName();

        // Try to find existing user by email (account linking)
        User user = userRepository.findByEmailAndTenantId(email, "public")
            .map(existing -> linkAccount(existing, provider, providerId))
            .orElseGet(() -> provisionOAuth2User(email, provider, providerId));

        log.info("OAuth2 login: {} via {}", email, provider);
        return oAuth2User;
    }

    private User linkAccount(User user, String provider, String providerId) {
        // Link social account to existing local account
        if (user.getProvider() == AuthProvider.LOCAL) {
            user.setProvider(AuthProvider.valueOf(provider.toUpperCase()));
            user.setProviderId(providerId);
            return userRepository.save(user);
        }
        return user;
    }

    private User provisionOAuth2User(String email, String provider, String providerId) {
        User user = User.builder()
            .email(email)
            .password("")  // no password for OAuth2 users
            .tenantId("public")
            .provider(AuthProvider.valueOf(provider.toUpperCase()))
            .providerId(providerId)
            .status(UserStatus.ACTIVE)
            .build();

        return userRepository.save(user);
    }

    private String extractEmail(OAuth2User user, String provider) {
        return switch (provider.toLowerCase()) {
            case "google" -> user.getAttribute("email");
            case "github" -> user.getAttribute("email");
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + provider);
        };
    }
}
