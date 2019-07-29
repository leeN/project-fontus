package de.tubs.cs.ias.asm_test;

import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;

import java.util.Optional;

public class DefaultClassInstrumentationStrategy implements ClassInstrumentationStrategy {

    private final ClassVisitor visitor;

    DefaultClassInstrumentationStrategy(ClassVisitor cv) {
        this.visitor = cv;
    }

    @Override
    public Optional<FieldVisitor> instrumentFieldInstruction(int access, String name, String descriptor, String signature, Object value, TriConsumer tc) {
        FieldVisitor fv = this.visitor.visitField(access, name, descriptor, signature, value);
        return Optional.of(fv);
    }

    @Override
    public Descriptor instrumentMethodInvocation(Descriptor desc) {
        return desc;
    }
}