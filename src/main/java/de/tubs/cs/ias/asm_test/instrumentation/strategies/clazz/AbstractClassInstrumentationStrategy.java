package de.tubs.cs.ias.asm_test.instrumentation.strategies.clazz;

import de.tubs.cs.ias.asm_test.TriConsumer;
import de.tubs.cs.ias.asm_test.instrumentation.strategies.AbstractInstrumentation;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.FieldVisitor;
import de.tubs.cs.ias.asm_test.utils.Logger;
import de.tubs.cs.ias.asm_test.utils.LogUtils;

import java.lang.invoke.MethodHandles;
import java.util.Optional;
import java.util.regex.Matcher;

public abstract class AbstractClassInstrumentationStrategy extends AbstractInstrumentation implements ClassInstrumentationStrategy {
    private static final Logger logger = LogUtils.getLogger();
    private final ClassVisitor visitor;

    AbstractClassInstrumentationStrategy(ClassVisitor visitor, String origDesc, String taintedDesc, String origQN, String taintedQN) {
        super(origDesc, taintedDesc, origQN, taintedQN);
        this.visitor = visitor;
    }

    @Override
    public Optional<FieldVisitor> instrumentFieldInstruction(int access, String name, String descriptor, String signature, Object value, TriConsumer tc) {
        Matcher descMatcher = this.descPattern.matcher(descriptor);
        if (descMatcher.find()) {
            String newDescriptor = descMatcher.replaceAll(this.taintedDesc);
            logger.info("Replacing {} field [{}]{}.{} with [{}]{}.{}", this.origQN, access, name, descriptor, access, name, newDescriptor);
            return Optional.of(this.visitor.visitField(access, name, newDescriptor, signature, value));
        }
        return Optional.empty();
    }
}
