<?php

namespace App\Security;

use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\PassportInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PasswordUpgradeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginFormAuthenticator extends AbstractAuthenticator
{
    private $userRepository;
    


    use TargetPathTrait;

    public const LOGIN_ROUTE = 'login';

    private UrlGeneratorInterface $urlGenerator;


    
    
    public function __construct(UserRepository $userRepository,UrlGeneratorInterface $urlGenerator)
    {
        $this->userRepository=$userRepository;
        $this->urlGenerator = $urlGenerator;
        dump("1");
        $test=($urlGenerator->getContext()->getPathInfo()); // renvoit "/afficher/fiche_annonce/21"
        
        return $test;
    }
    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route')=== 'login'
        && $request->isMethod('POST');
    }

    public function authenticate(Request $request): PassportInterface
    {
        // find a user based on an "email" form field
        /* dd($request->request->get('email')); */
        $user = $this->userRepository->findOneByEmail($request->request->get('email'));
        // dd($user);
        // ou findOneBy(['email'=> $request->request->get('email')])
        if (!$user) {
            throw new UserNotFoundException('Votre email ou mot de passe est invalide');
        }

        return new Passport($user, new PasswordCredentials($request->request->get('password')), [
            // and CSRF protection using a "csrf_token" field
            new CsrfTokenBadge('login_form', $request->request->get('csrf_token')),

            // and add support for upgrading the password hash
            /* new PasswordUpgradeBadge($request->get('password'), $this->userRepository) */
        ]);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        
        if ($targetPath = $this->getTargetPath($request->getSession(), $firewallName)) {
            return new RedirectResponse($targetPath);
        }

        
        return new RedirectResponse($this->urlGenerator->generate('accueil'));
    }
    
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        
        return new RedirectResponse($this->urlGenerator->generate('login'));
        
    }

    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }
}
