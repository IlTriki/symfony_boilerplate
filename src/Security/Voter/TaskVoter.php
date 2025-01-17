<?php

namespace App\Security\Voter;

use App\Entity\Task;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\User\UserInterface;

final class TaskVoter extends Voter
{
    public const EDIT = 'TASK_EDIT';
    public const VIEW = 'TASK_VIEW';
    public const DELETE = 'TASK_DELETE';
    public const CREATE = 'TASK_CREATE';

    protected function supports(string $attribute, mixed $subject): bool
    {
        // Pour CREATE, on n'a pas besoin de subject
        if ($attribute === self::CREATE) {
            return true;
        }

        // Pour les autres actions, on vérifie qu'on a bien une tâche
        return in_array($attribute, [self::EDIT, self::VIEW, self::DELETE])
            && $subject instanceof Task;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        // L'utilisateur doit être connecté
        if (!$user instanceof UserInterface) {
            return false;
        }

        // Les administrateurs peuvent tout faire
        if (in_array('ROLE_ADMIN', $user->getRoles())) {
            return true;
        }

        // Vérification des permissions selon l'action
        return match($attribute) {
            self::CREATE => $this->canCreate($user),
            self::EDIT => $this->canEdit($subject, $user),
            self::VIEW => $this->canView($subject, $user),
            self::DELETE => $this->canDelete($subject, $user),
            default => false,
        };
    }

    private function canCreate(UserInterface $user): bool
    {
        // Tout utilisateur connecté peut créer une tâche
        return true;
    }

    private function canEdit(Task $task, UserInterface $user): bool
    {
        // Seul l'auteur peut modifier sa tâche
        return $task->getAuthor() === $user;
    }

    private function canView(Task $task, UserInterface $user): bool
    {
        // Un utilisateur peut voir uniquement ses propres tâches
        return $task->getAuthor() === $user;
    }

    private function canDelete(Task $task, UserInterface $user): bool
    {
        // Les utilisateurs standards ne peuvent pas supprimer de tâches
        // Seuls les admins peuvent (déjà géré dans voteOnAttribute)
        return false;
    }
}
