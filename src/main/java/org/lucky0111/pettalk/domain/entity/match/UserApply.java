package org.lucky0111.pettalk.domain.entity.match;

import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.lucky0111.pettalk.domain.common.BaseTimeEntity;
import org.lucky0111.pettalk.domain.common.Status;
import org.lucky0111.pettalk.domain.entity.PetUser;
import org.lucky0111.pettalk.domain.entity.Trainer;

@Setter
@Getter
@Entity
@Table(name = "user_applies", indexes = {
        @Index(name = "idx_user_apply_user", columnList = "user_id"),
        @Index(name = "idx_user_apply_trainer", columnList = "trainer_id"),
        @Index(name = "idx_user_apply_status", columnList = "status"),
        @Index(name = "idx_user_trainer_status", columnList = "user_id, trainer_id, status")
})
public class UserApply extends BaseTimeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long applyId;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private PetUser petUser;

    @ManyToOne
    @JoinColumn(name = "trainer_id")
    private Trainer trainer;

    @Column(length = 500, nullable = false)
    private String content;

    private String imageUrl;

    private String videoUrl;

    @Column(nullable = false)
    private Status status;
}
