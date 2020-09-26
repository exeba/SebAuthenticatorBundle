<?php

namespace Seb\AuthenticatorBundle\Security\CredentialsCheckers;

use Seb\AuthenticatorBundle\Security\CredentialsCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class ImapCredentialsChecker implements CredentialsCheckerInterface
{
    private $imapMailbox;

    public function __construct(string $imapMailbox)
    {
        $this->imapMailbox = $imapMailbox;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        $mbox = @\imap_open($this->imapMailbox, $user->getUsername(), $credentials['password'], OP_HALFOPEN, 1);
        \imap_errors();
        \imap_alerts();

        if (false !== $mbox) {
            \imap_close($mbox);

            return true;
        } else {
            return false;
        }
    }
}
