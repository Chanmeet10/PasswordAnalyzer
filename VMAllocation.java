import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;

class CSP {
    String name;
    double cost;
    double reliability;
    double latency;
    List<VM> allocatedVMs;

    public CSP(String name, double cost, double reliability, double latency) {
        this.name = name;
        this.cost = cost;
        this.reliability = reliability;
        this.latency = latency;
        this.allocatedVMs = new ArrayList<>();
    }
}

class VM {
    String name;
    CSP allocatedCSP;

    public VM(String name) {
        this.name = name;
    }
}

class Chromosome implements Comparable<Chromosome> {
    int[] genes;
    double fitness;

    public Chromosome(int[] genes) {
        this.genes = genes;
    }

    @Override
    public int compareTo(Chromosome o) {
        return Double.compare(this.fitness, o.fitness);
    }
}

public class VMAllocation {

    private static final int POPULATION_SIZE = 100;
    private static final int MAX_GENERATIONS = 1000;
    private static final double MUTATION_RATE = 0.1;

    private List<VM> vms;
    private List<CSP> csps;

    public VMAllocation(List<VM> vms, List<CSP> csps) {
        this.vms = vms;
        this.csps = csps;
    }

    public Chromosome optimizeAllocation() {
        List<Chromosome> population = initializePopulation();
        for (int generation = 0; generation < MAX_GENERATIONS; generation++) {
            evaluatePopulation(population);
            List<Chromosome> newPopulation = new ArrayList<>();
            while (newPopulation.size() < POPULATION_SIZE) {
                Chromosome parent1 = selectParent(population);
                Chromosome parent2 = selectParent(population);
                Chromosome child = crossover(parent1, parent2);
                mutate(child);
                newPopulation.add(child);
            }
            population = newPopulation;
        }
        Collections.sort(population);
        return population.get(0);
    }

    private List<Chromosome> initializePopulation() {
        List<Chromosome> population = new ArrayList<>();
        int[] genes = new int[vms.size()];

        // Calculate the number of VMs per CSP
        int vmsPerCSP = vms.size() / csps.size();
        int remainder = vms.size() % csps.size();

        // Assign VMs to CSPs evenly
        int vmIndex = 0;
        for (int i = 0; i < csps.size(); i++) {
            int vmsToAllocate = (i < remainder) ? vmsPerCSP + 1 : vmsPerCSP;
            for (int j = 0; j < vmsToAllocate; j++) {
                genes[vmIndex % vms.size()] = i;
                vmIndex++;
            }
        }

        // Shuffle remaining VMs and assign them randomly to CSPs
        List<Integer> remainingVMs = new ArrayList<>();
        for (int i = csps.size(); i < vms.size(); i++) {
            remainingVMs.add(i);
        }
        Collections.shuffle(remainingVMs);
        int remainingIndex = 0;
        for (int i = vmIndex; i < vms.size(); i++) {
            genes[i] = remainingVMs.get(remainingIndex) % csps.size();
            remainingIndex++;
        }

        // Create initial population
        for (int i = 0; i < POPULATION_SIZE; i++) {
            population.add(new Chromosome(genes.clone()));
        }

        return population;
    }

    private int[] shuffleArray(int[] array) {
        Random rand = new Random();
        for (int i = array.length - 1; i > 0; i--) {
            int index = rand.nextInt(i + 1);
            int temp = array[index];
            array[index] = array[i];
            array[i] = temp;
        }
        return array;
    }

    private void evaluatePopulation(List<Chromosome> population) {
        for (Chromosome chromosome : population) {
            double totalCost = 0;
            double totalReliability = 1;
            double totalLatency = 0;
            for (int i = 0; i < chromosome.genes.length; i++) {
                int cspIndex = chromosome.genes[i];
                CSP csp = csps.get(cspIndex);
                totalCost += csp.cost;
                totalReliability *= csp.reliability;
                totalLatency += csp.latency;
            }
            double fitness = 0.3 * totalCost + 0.2 * (1 - totalReliability) + 0.5 * totalLatency;
            chromosome.fitness = fitness;
        }
    }

    private Chromosome selectParent(List<Chromosome> population) {
        Collections.shuffle(population);
        int tournamentSize = 5;
        List<Chromosome> tournament = population.subList(0, tournamentSize);
        Collections.sort(tournament);
        return tournament.get(0);
    }

    private Chromosome crossover(Chromosome parent1, Chromosome parent2) {
        int[] childGenes = new int[vms.size()];
        int crossoverPoint = new Random().nextInt(vms.size());
        for (int i = 0; i < crossoverPoint; i++) {
            childGenes[i] = parent1.genes[i];
        }
        for (int i = crossoverPoint; i < vms.size(); i++) {
            childGenes[i] = parent2.genes[i];
        }
        return new Chromosome(childGenes);
    }

    private void mutate(Chromosome chromosome) {
        for (int i = 0; i < chromosome.genes.length; i++) {
            if (Math.random() < MUTATION_RATE) {
                chromosome.genes[i] = new Random().nextInt(csps.size());
            }
        }
    }

    public static void main(String[] args) {
        List<CSP> csps = Arrays.asList(
                new CSP("CSP1", 100, 0.9, 10),
                new CSP("CSP2", 120, 0.95, 8),
                new CSP("CSP3", 150, 0.85, 12),
                new CSP("CSP4", 110, 0.92, 9),
                new CSP("CSP5", 130, 0.88, 11));

        List<VM> vms = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            vms.add(new VM("VM" + i));
        }

        VMAllocation geneticAlgorithm = new VMAllocation(vms, csps);
        Chromosome bestAllocation = geneticAlgorithm.optimizeAllocation();

        // Print the result
        System.out.println("CSP\tCost\tReliability\tLatency\tAllocated VMs");
        double totalCost = 0;
        double totalReliability = 1;
        double totalLatency = 0;
        for (int i = 0; i < bestAllocation.genes.length; i++) {
            int cspIndex = bestAllocation.genes[i];
            CSP csp = csps.get(cspIndex);
            System.out.print(csp.name + "\t" + csp.cost + "\t" + csp.reliability + "\t\t" + csp.latency + "\t\t");
            VM vm = vms.get(i);
            vm.allocatedCSP = csp;
            csp.allocatedVMs.add(vm);
            System.out.print(vm.name);
            if (i < bestAllocation.genes.length - 1) {
                System.out.print(", ");
            }
            System.out.println();
            totalCost += csp.cost;
            totalReliability *= csp.reliability;
            totalLatency += csp.latency;
        }
        System.out.println("\nTotal Cost: " + totalCost);
        System.out.println("Total Reliability: " + totalReliability);
        System.out.println("Total Latency: " + totalLatency);

        // Calculate and print the function value
        double functionValue = 0.3 * totalCost + 0.2 * (1 - totalReliability) + 0.5 * totalLatency;
        System.out.println("\nObjective Function Value: " + functionValue);

        // Print VM allocation
        System.out.println("\nVM Allocation:");
        for (CSP csp : csps) {
            System.out.print(csp.name + ": ");
            for (VM vm : csp.allocatedVMs) {
                System.out.print(vm.name + " ");
            }
            System.out.println();
        }
    }
}
