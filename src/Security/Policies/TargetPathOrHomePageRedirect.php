<?php

namespace Seb\AuthenticatorBundle\Security\Policies;

use Symfony\Component\Security\Http\HttpUtils;

class TargetPathOrHomePageRedirect extends ChainedSuccessfulAuthenticationPolicies
{
    public function __construct(HttpUtils $httpUtils, $homePagePath = 'homepage')
    {
        parent::__construct(new TargetPathRedirect(), new SimpleRedirect($httpUtils, $homePagePath));
    }
}
