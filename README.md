# InfraHash

## Introduction

This is a practice project ment to prepare developers for the Infrastructure SSLE. With that in mind it is stuctured and administrated in a similar way to the SSLE but will have a different prompt and set of requirements then the actual exam. This practice exam  will also have different time requirements to the exam being that most will not have the ability to take time off to work on it. With this in mind it is intended to take 10 business days or 80 hours total to complete but doesn't have a strict time window. It is up to the developer taking this exam to track there time to ensure they are staying on schedule. This exam is intended to be open ended to allow for many different solutions so there are few specific requirements on tools or resources.

Note: Currently there is no rubric for this exam but general scoring follows the breakdown:

    - 10% Planning
    - 70% Development
    - 20% Panel
    - If deployment fails it is an autoimatic failure if can't be resolved within 15min

### Cloudless Accommodation

If the developer wants to completely avoid using any cloud to avoid cost the recommendation is using LocalStack with terraform to emulate IAC in a cloud environment. This will allow for the majority of the functionality but will fo course come with a large initial setup cost for those who haven't used it before. If going cloudless recommendation is to take not start the practice exam until getting an initial hello world project deployed with LocalStack and Terraform to avoid excessive debugging during the practice exam.

## Instructions

Please read over all instructions and the given scenario before asking any questions. This practice exam is broken up into three phases that are as follows:

### Planning

The first 4-8 hours of the exam are intended for planning and development of an infrastructure diagram. The proctor is available to answer any clarification questions during this time. Once complete the proctor will review the overall development plan and diagram with the developer to ensure there wont be any major unnecessary costs. During the review the proctor can also be considered the stackholder so any adjustments or additions to the requirements can be made at this time. The review should be done where both the developer and proctor can have a conversation while both looking at the diagram however if that is not possible accomidations can be made.

### Development

Once the planning phase has been completed the developer can begin development. Development is expected to take the rest of the time and can be done on any official platform (DSOP, R2D2, ...) or personal repository. Multiple repos can also be used for different components of the project. During this time the proctor is still available for any questions. All resources are able to be used for this exam as long as they have appropriate justification and complete the requirements however it is advised not to depend on any tool too much as not all tools will be available for the actual exam.

### Panel

After development is complete the developer will be required to demonstrate there project to the proctor. The general flow of the panel is as follows:

1. Start deployment of infrastructure since it usually takes awhile.
2. Overview of development going through initial design, changes during development and major design decisions.
3. Any questions the proctor has on the design decisions that were made.
4. Demonstration of local and cloud deployment syncing.
5. Demonstration of local and cloud deployment autoscaling in reaction to high workload.
6. Demonstration of a live update to local and cloud infrastructure through managment systems.
7. Start destruction of infrastructure.
8. Any additional questions of the demonstrations.
9. Break for final grade and closing the practice exam.

## Scenario 

InfraHash Inc., a cybersecurity research organization specializing in password recovery and cryptographic analysis, has developed a proprietary password cracking service used for ethical penetration testing and assisting clients in recovering lost credentials. While the service is highly effective, its current deployment process is outdated and lacks the flexibility required for modern use cases. To address this, InfraHash Inc. is seeking to modify the service to make it rapidly deployable in both cloud and remote environments. The goal is to enable dynamic scaling in cloud environments to handle high workloads efficiently, while also ensuring the service remains lightweight and portable for deployment in remote or offline scenarios.

## Requirements

### Service

1. The application must be containerized for both deployments.
2. The application must use an external database.

### Deployments

1. There must be both a cloud based deployment option and a local (non-cloud) deployment option.
2. Deployments must utilized IAC.
3. Deployment process must be streamlined for the end user (No more then 3 commands to deploy all of the infrastructure).
4. All credentials must be handeled securly and secrets must be rotated weekly.
5. Deployments must implement autoscaling.
6. Deployments must have the option to be able to connect to one another and sync databases.
7. Deployments must have a dynamic managment strategy
    - Managment node for cloud with tools such as ansible, k9s, ...
    - Anything goes for the local deployment as long as it allows for dynamic changes
8. Logging must be implemented for the cloud deployment.

### Other

1. An infrastructure diagram must be created and approved showing all deployed resources and network flow.

## Other Considerations

1. Efficiency in the cloud environment. There could be many remote clients that want to share data with the main cloud instance so adding components to accommodate large volumes of traffic (Caches, Queues, ...)
2. Maintenance. This project is ment to be handed off and maintained by the client once development is complete so ensure proper documentation, CI/CD and consideration for updates.
3. Availability. There isn't any SLA required for this but ensuring the infrastrucuture is robust is still important.
