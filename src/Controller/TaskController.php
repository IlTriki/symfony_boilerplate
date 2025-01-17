<?php

namespace App\Controller;

use App\Entity\Task;
use App\Form\TaskType;
use App\Repository\TaskRepository;
use App\Security\Voter\TaskVoter;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

#[Route('/task')]
class TaskController extends AbstractController
{
    #[Route('/', name: 'task_index', methods: ['GET'])]
    public function index(TaskRepository $taskRepository): Response
    {
        try {
            // Si l'utilisateur est admin, on montre toutes les tâches
            if ($this->isGranted('ROLE_ADMIN')) {
                $tasks = $taskRepository->findAll();
            } else {
                // Sinon, on montre uniquement ses tâches
                $tasks = $taskRepository->findBy(['author' => $this->getUser()]);
            }

            return $this->render('task/index.html.twig', [
                'tasks' => $tasks,
            ]);
        } catch (AccessDeniedException $e) {
            $this->addFlash('error', 'Vous n\'avez pas accès à cette page.');
            return $this->redirectToRoute('app_login');
        }
    }

    #[Route('/new', name: 'task_new', methods: ['GET', 'POST'])]
    public function new(Request $request, EntityManagerInterface $entityManager): Response
    {
        try {
            $this->denyAccessUnlessGranted(TaskVoter::CREATE);

            $task = new Task();
            $task->setCreatedAt(new \DateTimeImmutable());
            $task->setAuthor($this->getUser());
            
            $form = $this->createForm(TaskType::class, $task);
            $form->handleRequest($request);

            if ($form->isSubmitted() && $form->isValid()) {
                $entityManager->persist($task);
                $entityManager->flush();

                $this->addFlash('success', 'La tâche a été créée avec succès.');
                return $this->redirectToRoute('task_index');
            }

            return $this->render('task/new.html.twig', [
                'task' => $task,
                'form' => $form,
            ]);
        } catch (AccessDeniedException $e) {
            $this->addFlash('error', 'Vous n\'avez pas les droits pour créer une tâche.');
            return $this->redirectToRoute('task_index');
        }
    }

    #[Route('/{id}', name: 'task_show', methods: ['GET'])]
    public function show(Task $task): Response
    {
        try {
            $this->denyAccessUnlessGranted(TaskVoter::VIEW, $task);
            return $this->render('task/show.html.twig', [
                'task' => $task,
            ]);
        } catch (AccessDeniedException $e) {
            $this->addFlash('error', 'Vous n\'avez pas accès à cette tâche.');
            return $this->redirectToRoute('task_index');
        }
    }

    #[Route('/{id}/edit', name: 'task_edit', methods: ['GET', 'POST'])]
    public function edit(Request $request, Task $task, EntityManagerInterface $entityManager): Response
    {
        try {
            $this->denyAccessUnlessGranted(TaskVoter::EDIT, $task);

            $form = $this->createForm(TaskType::class, $task);
            $form->handleRequest($request);

            if ($form->isSubmitted() && $form->isValid()) {
                $task->setUpdatedAt(new \DateTimeImmutable());
                $entityManager->flush();

                $this->addFlash('success', 'La tâche a été modifiée avec succès.');
                return $this->redirectToRoute('task_index');
            }

            return $this->render('task/edit.html.twig', [
                'task' => $task,
                'form' => $form,
            ]);
        } catch (AccessDeniedException $e) {
            $this->addFlash('error', 'Vous n\'avez pas les droits pour modifier cette tâche.');
            return $this->redirectToRoute('task_index');
        }
    }

    #[Route('/{id}', name: 'task_delete', methods: ['POST'])]
    public function delete(Request $request, Task $task, EntityManagerInterface $entityManager): Response
    {
        try {
            $this->denyAccessUnlessGranted(TaskVoter::DELETE, $task);

            if ($this->isCsrfTokenValid('delete'.$task->getId(), $request->request->get('_token'))) {
                $entityManager->remove($task);
                $entityManager->flush();
                $this->addFlash('success', 'La tâche a été supprimée avec succès.');
            }

            return $this->redirectToRoute('task_index');
        } catch (AccessDeniedException $e) {
            $this->addFlash('error', 'Vous n\'avez pas les droits pour supprimer cette tâche.');
            return $this->redirectToRoute('task_index');
        }
    }
}
